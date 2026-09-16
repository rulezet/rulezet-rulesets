rule Virus_Hijack_Trojan_GenericKDZ_105924_470_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_470_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6755c6c045bfd39ab2c4fe6773592668aabbb332392f9e0210b97c45c3ddb97d"

  strings:
    $s1 = "FS`LOcO" fullword ascii
    $s2 = "K}ARna" fullword ascii
    $s3 = "b=(ERiA" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}