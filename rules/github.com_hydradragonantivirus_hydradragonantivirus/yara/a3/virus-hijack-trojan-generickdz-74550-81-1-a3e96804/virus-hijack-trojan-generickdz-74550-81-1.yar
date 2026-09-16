rule Virus_Hijack_Trojan_GenericKDZ_74550_81_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.74550_81_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4a7d8717a331fc4cdf46d7d309b9274f96d9d835b82f56163dc6fd1a04d155ab"

  strings:
    $s1 = "qUEt?rJ" fullword ascii
    $s2 = "Chun>1" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}