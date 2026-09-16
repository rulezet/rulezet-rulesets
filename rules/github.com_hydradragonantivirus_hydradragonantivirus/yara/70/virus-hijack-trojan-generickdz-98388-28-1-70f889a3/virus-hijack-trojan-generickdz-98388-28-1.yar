rule Virus_Hijack_Trojan_GenericKDZ_98388_28_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98388_28_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "12e95dc7b163757cd87ac1bd1d9e97c88e0e5e2d2c65ed0c1acd7320da208f6e"

  strings:
    $s1 = "deVA*<" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}