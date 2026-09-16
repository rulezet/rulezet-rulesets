rule Virus_Hijack_Trojan_GenericKDZ_105920_7_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105920_7_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ff651c984066d9a1e2523614ded9181b3fa8cdfe28925c0c7804c22f276fb720"

  strings:
    $s1 = "leud#~" fullword ascii
    $s2 = "x]hevI" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}