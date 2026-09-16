rule Virus_Hijack_Trojan_GenericKDZ_98113_261_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_261_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7bd4b7f90bfba775340a76010c751882eb30f83d6986495eb060a0752d0445b8"

  strings:
    $s1 = "turk].BaQ" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}