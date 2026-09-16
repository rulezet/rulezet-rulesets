rule Virus_Hijack_Trojan_GenericKDZ_98113_195_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_195_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "63cf452deeadbd1b291b06d0e23549b4945f459387b2fd5e0fd84a1ca751f88d"

  strings:
    $s1 = "kiRI[53" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}