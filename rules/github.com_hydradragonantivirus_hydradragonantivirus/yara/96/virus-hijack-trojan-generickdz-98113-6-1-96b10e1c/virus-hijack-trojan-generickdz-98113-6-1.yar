rule Virus_Hijack_Trojan_GenericKDZ_98113_6_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_6_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4f48b540207249b2715d5e563d6eceff4edbd2a53d1d5275b9cf6f6bbefa6fc4"

  strings:
    $s1 = "iKra;]" fullword ascii
    $s2 = "f)LosE" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}