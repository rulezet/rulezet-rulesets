rule Virus_Hijack_Trojan_GenericKDZ_105924_327_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_327_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "222da35ad6294622be561d74e100a47fe57453b3d2774466240c4cce6725aee1"

  strings:
    $s1 = ")beRE`%" fullword ascii
    $s2 = "]&vINA" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}