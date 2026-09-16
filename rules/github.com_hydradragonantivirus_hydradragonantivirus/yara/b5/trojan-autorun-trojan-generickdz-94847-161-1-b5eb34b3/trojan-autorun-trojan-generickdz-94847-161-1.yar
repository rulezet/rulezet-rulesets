rule Trojan_Autorun_Trojan_GenericKDZ_94847_161_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKDZ.94847_161_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3b423c2b32776b14bffb21b1cc2d3901cf79ddcb9ac4a52fc2836437ef561e88"

  strings:
    $s1 = "\"daRr u" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}