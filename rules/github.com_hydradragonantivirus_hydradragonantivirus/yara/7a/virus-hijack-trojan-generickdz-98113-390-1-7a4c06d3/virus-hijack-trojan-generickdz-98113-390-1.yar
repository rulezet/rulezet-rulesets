rule Virus_Hijack_Trojan_GenericKDZ_98113_390_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_390_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "47ee5006faad3043966816ce034016d2597f86e18f1de69c6cacfbeb1576202b"

  strings:
    $s1 = "dolI$vy" fullword ascii
    $s2 = "SIsH[q" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}