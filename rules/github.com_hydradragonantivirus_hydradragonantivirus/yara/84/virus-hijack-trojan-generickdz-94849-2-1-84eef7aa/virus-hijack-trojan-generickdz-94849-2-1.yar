rule Virus_Hijack_Trojan_GenericKDZ_94849_2_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.94849_2_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0ade55d897129fcc54ac5cd0ffdad5b3f78bbf79789a65751feab85f469fc94e"

  strings:
    $s1 = "L\"GARN." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}