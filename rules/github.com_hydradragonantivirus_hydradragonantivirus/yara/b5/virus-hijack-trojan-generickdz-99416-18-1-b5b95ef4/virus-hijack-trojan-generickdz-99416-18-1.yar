rule Virus_Hijack_Trojan_GenericKDZ_99416_18_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.99416_18_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "32774007e01ecb75eb161031c2fd469cf41e57318a3b76bcd2f228ec9e552a7f"

  strings:
    $s1 = "PIze;P" fullword ascii
    $s2 = "8<KEnd" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}