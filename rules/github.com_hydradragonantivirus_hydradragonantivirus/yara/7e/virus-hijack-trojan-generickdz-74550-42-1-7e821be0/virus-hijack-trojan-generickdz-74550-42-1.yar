rule Virus_Hijack_Trojan_GenericKDZ_74550_42_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.74550_42_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "783aea5157298a1bdaa4571f87e1c3b60c1228945e3c06f3bdfacdcd9d689e2b"

  strings:
    $s1 = ">kEeP;" fullword ascii
    $s2 = "9'`bRaN" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}