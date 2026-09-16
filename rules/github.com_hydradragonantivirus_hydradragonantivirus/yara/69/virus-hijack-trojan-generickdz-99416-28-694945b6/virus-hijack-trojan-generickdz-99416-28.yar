rule Virus_Hijack_Trojan_GenericKDZ_99416_28 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.99416_28.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "72f93051888fd981e2c3fb92f2d43a4d51355842e4ed999651b00e07a2aee3f8"

  strings:
    $s1 = "YUser, Marketing User, Manufacturing User, Purcha" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}