rule Virus_Hijack_Trojan_GenericKDZ_105924_304_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_304_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9ccdfc518d1d0520690bb72a80d8105f5f20310fdabb40c0c8b5323b29302c7e"

  strings:
    $s1 = "piNd>j.X4" fullword ascii
    $s2 = "{*OILY" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}