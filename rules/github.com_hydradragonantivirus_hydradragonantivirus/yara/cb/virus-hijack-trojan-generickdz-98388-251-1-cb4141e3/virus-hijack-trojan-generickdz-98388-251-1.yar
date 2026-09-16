rule Virus_Hijack_Trojan_GenericKDZ_98388_251_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98388_251_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3953c888036ebbe3321a3676a6dd8013a4a81748facbeb66a1bf58931626ee1f"

  strings:
    $s1 = "rAmE{K" fullword ascii
    $s2 = "A<gAne" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}