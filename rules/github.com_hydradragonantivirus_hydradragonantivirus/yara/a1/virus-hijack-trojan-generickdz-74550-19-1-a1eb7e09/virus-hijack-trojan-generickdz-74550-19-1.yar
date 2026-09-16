rule Virus_Hijack_Trojan_GenericKDZ_74550_19_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.74550_19_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d9387c36febcdbb455e02e9c9693a211a3873d214825d6d03b70351aa69eb6d0"

  strings:
    $s1 = "$$FOal%~nW" fullword ascii
    $s2 = "G`EKER" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}