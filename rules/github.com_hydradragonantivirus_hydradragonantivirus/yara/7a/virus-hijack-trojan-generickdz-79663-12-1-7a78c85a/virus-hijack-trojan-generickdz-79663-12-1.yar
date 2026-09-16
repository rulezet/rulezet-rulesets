rule Virus_Hijack_Trojan_GenericKDZ_79663_12_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.79663_12_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8585a44b301a54f8889f6000189790434e75e98e1964c659ed16f20196714b29"

  strings:
    $s1 = "cotta;U%{D\\" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}