rule Virus_Hijack_Trojan_GenericKDZ_79663_61_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.79663_61_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4db47960436abd06d2b5a084c73341ccc7e82a8f56f144866d5674c4b2df3a0b"

  strings:
    $s1 = "plea;\"" fullword ascii
    $s2 = "Fj[tROD" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}