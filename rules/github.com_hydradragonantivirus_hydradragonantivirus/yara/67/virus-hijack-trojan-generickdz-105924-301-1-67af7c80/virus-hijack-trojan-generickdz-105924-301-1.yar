rule Virus_Hijack_Trojan_GenericKDZ_105924_301_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_301_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5da34c7fac8878723a8929a29d6a962c0235119fbabed7928e045f5fb6e0671c"

  strings:
    $s1 = "F(WOKE" fullword ascii
    $s2 = ">LUbe]" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}