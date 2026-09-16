rule Virus_Hijack_Trojan_GenericKDZ_105924_396_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_396_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1a8d538fdf40543f3cfe1b3cb7833536df39a35bcab2c1bc646306af033884f1"

  strings:
    $s1 = "tiGE`P!" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}