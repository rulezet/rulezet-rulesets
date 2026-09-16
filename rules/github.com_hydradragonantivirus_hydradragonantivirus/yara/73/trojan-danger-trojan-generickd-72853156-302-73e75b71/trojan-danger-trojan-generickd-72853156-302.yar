rule Trojan_Danger_Trojan_GenericKD_72853156_302 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.72853156_302.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "459cee6e48a1a0664b9b0cacf4dc650bddaa0b2510e8ef01ec8dbd100a4f19a1"

  strings:
    $s1 = "p{wusp" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}