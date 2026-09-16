rule Virus_Hijack_Trojan_GenericKDZ_98113_337_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_337_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "70e7c111670fdc5d83dbd64aecb1b65999670f883984d9913c3b3d32c863d931"

  strings:
    $s1 = "tk]\"tolT" fullword ascii
    $s2 = "ARiA:O" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}