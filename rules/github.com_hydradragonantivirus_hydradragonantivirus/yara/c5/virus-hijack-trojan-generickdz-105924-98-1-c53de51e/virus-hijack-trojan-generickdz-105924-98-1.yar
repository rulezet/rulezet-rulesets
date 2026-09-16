rule Virus_Hijack_Trojan_GenericKDZ_105924_98_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_98_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "25cff4a02b9d9f288706418a6a36d29089c50eff1881ec5a00a51ea1cb0870dc"

  strings:
    $s1 = "7lt\"celt" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}