rule _Trojan_Hooker_Win32_Floxif_A_30_Trojan_Hooker_Win32_Floxif_A_38_249 {
  meta:
    description = "datamaliciousorder - from files Trojan.Hooker_Win32.Floxif.A_30.vir, Trojan.Hooker_Win32.Floxif.A_38.vir, Trojan.Hooker_Win32.Floxif.A_42.vir, Trojan.Hooker_Win32.Floxif.A_5.vir, Trojan.Hooker_Win32.Floxif.A_51.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7b85a4e86d717bd4c713fdbf3c8506ce813f0e8686f1bf8313a818180de156c4"
    hash2       = "4a1c7bc29536e8420d7fc01605c1044631613f34dec8d868897055bc65435bec"
    hash3       = "60fb908f04787144ac410bab3548e36d760d08e2ff25819e62e647cfa1a41817"
    hash4       = "08d30e8075c04ed429882f2da2bbef678b34eae6f6866eb9b1bd46a9523dde74"
    hash5       = "dcd5a75a38942995fe1279e1cb474960879a75d9d10620cabcfb75b29cda7563"

  strings:
    $x1  = "TPerlRegEx.Compile() - Error in regex at offset %d: %s" fullword ascii
    $s2  = "TPerlRegEx.Compile() - Please specify a regular expression in RegEx first" fullword ascii
    $s3  = "TEnvironment.ReadSystem: Operating system version is: " fullword ascii
    $s4  = " failed to be forwarded to server " fullword ascii
    $s5  = "TConfiguration.LoadFromFile: Configuration file loaded successfully." fullword ascii
    $s6  = " forwarded to server " fullword ascii
    $s7  = "A local DNS proxy which improves the performance of your computer." fullword ascii
    $s8  = "TCommunicationChannel.Initialize: WSAStartup function failed." fullword ascii
    $s9  = "TTracer.Trace: The tracer agent must be set before calling this method." fullword ascii
    $s10 = "TBootstrapper.StopSystem: Stopping DNS resolver..." fullword ascii
    $s11 = "TBootstrapper.StartSystem: Loading configuration file..." fullword ascii
    $s12 = "TEnvironment.ReadSystem: Reading IP configuration..." fullword ascii
    $s13 = "THostsCache.LoadFromFileEx: Loading hosts cache items from file \"" fullword ascii
    $s14 = " failed with Windows Sockets error code " fullword ascii
    $s15 = "Acrylic DNS Proxy" fullword ascii
    $s16 = " received from server " fullword ascii
    $s17 = "Septenary" fullword ascii
    $s18 = "TBootstrapper.StartSystem: Loading hosts cache items..." fullword ascii
    $s19 = "Octonary" fullword ascii
    $s20 = " sent to client " fullword ascii

  condition:
    (uint16(0) == 0x5a4d and (1 of ($x*) and 4 of them)
    ) or (all of them)
}