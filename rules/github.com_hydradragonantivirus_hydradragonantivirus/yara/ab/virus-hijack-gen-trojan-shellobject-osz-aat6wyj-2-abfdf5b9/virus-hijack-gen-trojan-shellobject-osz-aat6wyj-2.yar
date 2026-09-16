rule Virus_Hijack_Gen_Trojan_ShellObject_oSZ_aaT6Wyj_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.oSZ@aaT6Wyj_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "79d37ba55b73d37d28c6322fc2b59774bcbf18ce42afd072ae3aaa374a7b6bd8"

  strings:
    $s1 = "6whole number for purposes of license quantity requirements." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}