rule Virus_Hijack_Trojan_GenericKDZ_98388_146_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98388_146_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f6449c67a0ca30cfce3bd20f362b1a687d3528bd806471c557deda59262a15f8"

  strings:
    $s1 = "THEn!" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}