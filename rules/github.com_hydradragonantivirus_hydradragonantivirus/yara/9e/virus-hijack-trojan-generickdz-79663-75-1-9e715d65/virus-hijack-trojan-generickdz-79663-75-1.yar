rule Virus_Hijack_Trojan_GenericKDZ_79663_75_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.79663_75_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "97cdcb4666c9adeeffc9db87df5f31cb796ef733377edb149aacdb5b6c8b7411"

  strings:
    $s1 = "EK*pIne" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}