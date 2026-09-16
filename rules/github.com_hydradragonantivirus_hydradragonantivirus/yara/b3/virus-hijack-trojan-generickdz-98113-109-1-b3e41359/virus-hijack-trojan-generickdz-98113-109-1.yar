rule Virus_Hijack_Trojan_GenericKDZ_98113_109_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_109_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "733aae5b00ccff52b7350f5c12cbcb25da4a748e88fb213d66cf1ab10e25c85b"

  strings:
    $s1 = "U&diEr" fullword ascii
    $s2 = ")CHEE#" fullword ascii
    $s3 = "C#kInD" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}