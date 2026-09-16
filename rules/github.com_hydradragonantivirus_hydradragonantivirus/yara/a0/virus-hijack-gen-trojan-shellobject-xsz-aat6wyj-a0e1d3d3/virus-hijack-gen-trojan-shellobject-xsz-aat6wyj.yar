rule Virus_Hijack_Gen_Trojan_ShellObject_xSZ_aaT6Wyj {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.xSZ@aaT6Wyj.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3586bf859cc0273fb02b8e7d7c76cda0326522786176b689d73e14e073c35aba"

  strings:
    $s1 = "~whole number for purposes of license quantity requirements." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}