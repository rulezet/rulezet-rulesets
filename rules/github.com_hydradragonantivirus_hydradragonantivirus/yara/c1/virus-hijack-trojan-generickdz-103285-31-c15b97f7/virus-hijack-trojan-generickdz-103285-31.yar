rule Virus_Hijack_Trojan_GenericKDZ_103285_31 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_31.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d79a141af6536aca750e8f6eb7bb193b250a2e37cbaa3bf9a9f80bd9c236ddb1"

  strings:
    $s1 = "CrIb:d" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}