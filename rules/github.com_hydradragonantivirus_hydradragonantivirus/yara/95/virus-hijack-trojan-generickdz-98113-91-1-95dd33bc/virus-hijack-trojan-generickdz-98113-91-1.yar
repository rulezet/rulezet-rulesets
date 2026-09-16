rule Virus_Hijack_Trojan_GenericKDZ_98113_91_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_91_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8b810c81994449387852f7822d7ea621ee33491aa32c83ba3d5d66b8f129e957"

  strings:
    $s1 = "E[,jEst" fullword ascii
    $s2 = "o<wOnE" fullword ascii
    $s3 = "in:EchE" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}