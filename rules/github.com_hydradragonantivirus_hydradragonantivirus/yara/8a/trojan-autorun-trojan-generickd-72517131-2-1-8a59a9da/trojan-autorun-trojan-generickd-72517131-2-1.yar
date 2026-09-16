rule Trojan_Autorun_Trojan_GenericKD_72517131_2_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKD.72517131_2_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "70bf3dfb7facbcffe54b1aff011f991e3dac66eb94c3097fc4f817cc961d3053"

  strings:
    $s1 = "licensed program on the processors where a licensed Oracle Database (Standard Edi" fullword ascii
    $s2 = "VUser, Marketing User, Manufacturing User, Purcha" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}