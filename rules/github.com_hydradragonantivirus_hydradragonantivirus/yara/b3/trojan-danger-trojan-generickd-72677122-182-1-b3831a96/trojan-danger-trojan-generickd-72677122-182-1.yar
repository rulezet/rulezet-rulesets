rule Trojan_Danger_Trojan_GenericKD_72677122_182_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.72677122_182_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "55c5ac440510e7c6ae0b3a4a4143042a4ceb5147d9e615bb9af20d456effbfaf"

  strings:
    $s1 = "dAsI!aH@" fullword ascii
    $s2 = ",[Hand" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}