rule Virus_Hijack_Trojan_GenericKDZ_105924_360_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_360_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "87d4828eacb39c1f5abc56210391d00db23932c2050b7321d6e47d6b30cd49cb"

  strings:
    $s1 = "f)HikE" fullword ascii
    $s2 = "S(BeaR" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}