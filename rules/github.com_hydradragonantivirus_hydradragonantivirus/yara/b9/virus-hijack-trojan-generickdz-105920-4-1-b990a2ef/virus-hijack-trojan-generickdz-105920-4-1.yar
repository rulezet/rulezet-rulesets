rule Virus_Hijack_Trojan_GenericKDZ_105920_4_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105920_4_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ea0e3ee6c36c13501d9cc511e5226e86375e53f39f0d9e9d91ac1d27c6875a67"

  strings:
    $s1 = "_@SniP" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}