rule Virus_Hijack_Trojan_GenericKDZ_105924_497_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_497_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "135ca9772292704992b22c37b2b8f2f5231e05016c14265f7f2d535415c883ad"

  strings:
    $s1 = "GroG}3~H" fullword ascii
    $s2 = "GAEn@J" fullword ascii
    $s3 = "loWn,H" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}