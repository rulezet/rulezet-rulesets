rule Virus_Hijack_Gen_Trojan_ShellObject_j8Z_ai6MB5n_3 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.j8Z@ai6MB5n_3.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d03c1ce07f01a5d6e72a84bf107c0bdf6c69adab8a67bf98f2348fc8a5f8bfba"

  strings:
    $s1 = "'HAmerica, call (800) MICROSOFT or see microsoft.com/info/nareturns.htm." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}