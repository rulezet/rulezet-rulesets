rule Virus_Hijack_Trojan_GenericKDZ_105924_81_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_81_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bf3cd045f7a86d9e4762c44cf8c4ee08da3bdd90889f26e824729d0eb496a9dc"

  strings:
    $s1 = "NPi>TiDe" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}