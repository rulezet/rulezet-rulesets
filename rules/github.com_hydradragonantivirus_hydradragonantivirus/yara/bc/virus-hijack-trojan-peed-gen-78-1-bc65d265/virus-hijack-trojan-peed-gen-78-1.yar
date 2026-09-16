rule Virus_Hijack_Trojan_Peed_Gen_78_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.Peed.Gen_78_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d78bb78aa89a2712a8c701a69358e0e611f8c476f4e9fa1d89c9620d3efa404b"

  strings:
    $s1 = "hObBy`'" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}