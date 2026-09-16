rule Virus_Hijack_Trojan_GenericKDZ_103285_333_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_333_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "02cc175e5ab7c8c1080d343790acb137e9f0b7c0d436aeb6b97c58681a0062db"

  strings:
    $s1 = "ewing Condition in IEC61966-2.1" fullword ascii
    $s2 = ",Reference V" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}