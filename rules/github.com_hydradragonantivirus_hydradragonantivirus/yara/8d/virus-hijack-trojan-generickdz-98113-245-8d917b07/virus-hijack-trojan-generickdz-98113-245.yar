rule Virus_Hijack_Trojan_GenericKDZ_98113_245 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_245.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f3108e6943730c71d22054cc35fbc9e45b573fd25693ad2d98a0ff9530ab4d5d"

  strings:
    $s1 = "D4. Language Packs and Proofing Tools. If you acq" fullword ascii
    $s2 = "DO NOT ALLOW TH" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}