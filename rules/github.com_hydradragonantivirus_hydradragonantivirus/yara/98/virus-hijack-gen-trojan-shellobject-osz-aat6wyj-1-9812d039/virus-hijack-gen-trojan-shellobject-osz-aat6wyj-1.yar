rule Virus_Hijack_Gen_Trojan_ShellObject_oSZ_aaT6Wyj_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.oSZ@aaT6Wyj_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "194779bbec8f347097a11d96967830c7df3479cbd22f01131f36dd5a94e78a80"

  strings:
    $s1 = "&0whole number for purposes of license quantity requirements." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}