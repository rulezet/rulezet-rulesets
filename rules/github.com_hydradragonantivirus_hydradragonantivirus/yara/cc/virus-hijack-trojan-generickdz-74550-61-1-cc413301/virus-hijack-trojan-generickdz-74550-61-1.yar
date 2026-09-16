rule Virus_Hijack_Trojan_GenericKDZ_74550_61_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.74550_61_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f37f464ea582b5a8463112954a203a8e5318a3dd4f5a45fe7b9f57cb137dd572"

  strings:
    $s1 = "rz&roTo " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}