import "pe"
rule _Trojan_Hooker_Win32_Floxif_A_30_Trojan_Hooker_Win32_Floxif_A_38_97 {
  meta:
    description = "datamaliciousorder - from files Trojan.Hooker_Win32.Floxif.A_30.vir, Trojan.Hooker_Win32.Floxif.A_38.vir, Trojan.Hooker_Win32.Floxif.A_42.vir, Trojan.Hooker_Win32.Floxif.A_51.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7b85a4e86d717bd4c713fdbf3c8506ce813f0e8686f1bf8313a818180de156c4"
    hash2       = "4a1c7bc29536e8420d7fc01605c1044631613f34dec8d868897055bc65435bec"
    hash3       = "60fb908f04787144ac410bab3548e36d760d08e2ff25819e62e647cfa1a41817"
    hash4       = "dcd5a75a38942995fe1279e1cb474960879a75d9d10620cabcfb75b29cda7563"

  strings:
    $x1  = "TIPv4Socks5DnsForwarder.Execute: The following error occurred while forwarding request ID " fullword ascii
    $x2  = "TIPv6TcpDnsForwarder.Execute: The following error occurred while forwarding request ID " fullword ascii
    $x3  = "TDnsOverHttpsDnsForwarder.Execute: The following error occurred while forwarding request ID " fullword ascii
    $x4  = "TIPv6Socks5DnsForwarder.Execute: The following error occurred while forwarding request ID " fullword ascii
    $x5  = "TIPv4TcpDnsForwarder.Execute: The following error occurred while forwarding request ID " fullword ascii
    $x6  = "TIPv4UdpDnsForwarder.Execute: The following error occurred while forwarding request ID " fullword ascii
    $s7  = "TIPv4TcpClientCommunicationChannel.Connect: Connection failed with Windows Sockets error code " fullword ascii
    $s8  = "TBootstrapper.StartSystem: Done loading configuration file." fullword ascii
    $s9  = "TBootstrapper.StopSystem: Done stopping DNS resolver." fullword ascii
    $s10 = "TIPv4TcpClientCommunicationChannel.ContinueReceive: Receiving failed with Windows Sockets reporting 0 bytes received." fullword ascii
    $s11 = "TDnsOverHttpsClientCommunicationChannel.SendToAndReceiveFrom: WinHttpReadData failed with error code " fullword ascii
    $s12 = "TDnsOverHttpsClientCommunicationChannel.SendToAndReceiveFrom: WinInet.InternetReadFile failed with error code " fullword ascii
    $s13 = "TIPv4TcpClientCommunicationChannel.ContinueSend: Sending failed with Windows Sockets reporting 0 bytes sent." fullword ascii
    $s14 = "TIPv6TcpClientCommunicationChannel.Send: Sending failed with Windows Sockets reporting 0 bytes sent." fullword ascii
    $s15 = "TIPv4TcpClientCommunicationChannel.Send: Sending failed with Windows Sockets reporting 0 bytes sent." fullword ascii
    $s16 = "TDualUdpServerCommunicationChannel.Bind: Binding to IPv4 address failed with Windows Sockets error code " fullword ascii
    $s17 = "TIPv6UdpClientCommunicationChannel.BindToDynamicPort: Binding failed with Windows Sockets error code " fullword ascii
    $s18 = "TDualUdpServerCommunicationChannel.SendTo: Sending to IPv6 address failed with Windows Sockets error code " fullword ascii
    $s19 = "TIPv6TcpClientCommunicationChannel.ContinueReceive: Receiving failed with Windows Sockets reporting 0 bytes received." fullword ascii
    $s20 = "TIPv6TcpClientCommunicationChannel.Receive: Receiving failed with Windows Sockets reporting 0 bytes received." fullword ascii

  condition:
    (uint16(0) == 0x5a4d and pe.imphash() == "9ef669a8b2317c8af0c586bfd5bee9dc" and (1 of ($x*) and 4 of them)
    ) or (all of them)
}