rule Virus_Hijack_Trojan_GenericKDZ_99416_44_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.99416_44_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7846899ee4cb38e268ecfde7b9475022682b69786dfb925b9ca6fe3c9c4b913f"

  strings:
    $s1 = "OLEO&m" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}