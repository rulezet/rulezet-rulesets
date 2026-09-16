rule Virus_Hijack_Trojan_GenericKDZ_105924_290_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_290_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "38757a64e21ee46f88a48597bc8ec794ecd98d0c00a46976a12ef141f8b6a03e"

  strings:
    $s1 = "MOre#*" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}