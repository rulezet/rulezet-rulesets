rule Virus_Hijack_Trojan_GenericKDZ_79663_63_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.79663_63_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "229bf0cb3cb72468ec7faf29104ed519059485fde9d7a97359c10d5de4856f16"

  strings:
    $s1 = "#pS[STIm" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}