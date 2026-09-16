rule Virus_Hijack_Trojan_GenericKDZ_98113_246_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_246_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b7522b367755328c91819d3bd782c1c6d154218726cb75ebf5e2f33bd3cdd776"

  strings:
    $s1 = "BLeB(Wd\\1" fullword ascii
    $s2 = "'zg&eddY" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}