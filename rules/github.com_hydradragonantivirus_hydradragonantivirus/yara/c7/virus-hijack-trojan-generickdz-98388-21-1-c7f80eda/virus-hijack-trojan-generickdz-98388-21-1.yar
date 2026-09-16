rule Virus_Hijack_Trojan_GenericKDZ_98388_21_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98388_21_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4d0c9ef620bf1a7c12d9a75c367813a0b4cb96d3bdb902441ca9f77d9a5073c3"

  strings:
    $s1 = "votaL#,$V" fullword ascii
    $s2 = "T,SHiH" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}