rule Trojan_Hooker_Trojan_GenericKD_73131157 {
  meta:
    description = "datamaliciousorder - file Trojan.Hooker_Trojan.GenericKD.73131157.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7ba682f25b565e1dd17309c98ffc218701d461afe82a90e97660fffaae00f5df"

  strings:
    $s1  = " System.Text.Encoding.GetEncoding(string) " fullword ascii
    $s2  = " COM+ Integration " fullword ascii
    $s3  = " Microsoft .NET Framework 3.0 " fullword ascii
    $s4  = " Supporting SecurityToken" fullword ascii
    $s5  = " Microsoft .NET Framework 3.0 SDK " fullword ascii
    $s6  = "Port: {4}" fullword ascii
    $s7  = "'ComPlus: Dispatch " fullword ascii
    $s8  = " HTTP Digest " fullword ascii
    $s9  = " HTTP SOAP " fullword ascii
    $s10 = " Listen()" fullword ascii
    $s11 = " via Header" fullword ascii
    $s12 = " Delegation " fullword ascii
    $s13 = "$Maintainer " fullword ascii
    $s14 = " Resolve " fullword ascii
    $s15 = "Open: {3}" fullword ascii
    $s16 = ":Maintainer " fullword ascii
    $s17 = " Windows Server 2003 " fullword ascii
    $s18 = " Impersonation " fullword ascii
    $s19 = " Reject " fullword ascii
    $s20 = " Peer {0} " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    8 of them
}