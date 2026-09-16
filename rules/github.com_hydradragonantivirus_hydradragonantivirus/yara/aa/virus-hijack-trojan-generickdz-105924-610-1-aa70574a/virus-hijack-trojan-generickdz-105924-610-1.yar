rule Virus_Hijack_Trojan_GenericKDZ_105924_610_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_610_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9c71b1596f6fe17341b941c292690d2137fc5f5deed5a5e2d66ed4b3a0281f06"

  strings:
    $s1 = "p:robE" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}