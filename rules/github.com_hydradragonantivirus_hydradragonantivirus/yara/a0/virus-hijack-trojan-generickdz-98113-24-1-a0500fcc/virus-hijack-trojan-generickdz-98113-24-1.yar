rule Virus_Hijack_Trojan_GenericKDZ_98113_24_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_24_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2f70b5b7f603af06e95deffcd8af05a14d0386135c7087715aeac6b3d49c2af8"

  strings:
    $s1 = "mAJO%pS" fullword ascii
    $s2 = "DouM>L" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}