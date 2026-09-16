rule Virus_Hijack_Trojan_GenericKDZ_105924_173_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_173_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7e6b9c0665cad5fe393165c2d277291635bb89429b0cc19eb4b5605d606bb916"

  strings:
    $s1 = "PHYSICAL;DR" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}