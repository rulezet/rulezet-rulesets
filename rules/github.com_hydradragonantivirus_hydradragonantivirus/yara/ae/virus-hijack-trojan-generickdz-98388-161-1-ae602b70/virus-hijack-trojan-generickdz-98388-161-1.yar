rule Virus_Hijack_Trojan_GenericKDZ_98388_161_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98388_161_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ad9d99d5352a6b7178cab84a60a5f9978ef52a6c38bc06c49b2c95a940da8865"

  strings:
    $s1 = "BRiM]9" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}