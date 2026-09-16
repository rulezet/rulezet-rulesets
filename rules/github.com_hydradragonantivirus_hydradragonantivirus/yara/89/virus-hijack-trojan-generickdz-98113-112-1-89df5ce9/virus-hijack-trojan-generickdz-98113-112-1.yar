rule Virus_Hijack_Trojan_GenericKDZ_98113_112_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_112_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6f6d22d2ae1072b4bcfe02b3e13c2d43b7802d90002e34caceceb5dd67e5be79"

  strings:
    $s1 = "pAIp{t]" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}