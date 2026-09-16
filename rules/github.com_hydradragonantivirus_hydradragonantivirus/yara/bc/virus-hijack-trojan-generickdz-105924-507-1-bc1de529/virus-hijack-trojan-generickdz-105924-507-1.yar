rule Virus_Hijack_Trojan_GenericKDZ_105924_507_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_507_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a77f3ff9bb8cf7c4c5d5f5604e43e0ddacfd0542f9eb6c6ea0c3d9fbd8c48cbd"

  strings:
    $s1 = "WeET;Z" fullword ascii
    $s2 = "'3,cOAk" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}