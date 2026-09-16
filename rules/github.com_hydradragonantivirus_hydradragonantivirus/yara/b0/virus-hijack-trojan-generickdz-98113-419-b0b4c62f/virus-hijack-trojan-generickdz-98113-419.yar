rule Virus_Hijack_Trojan_GenericKDZ_98113_419 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_419.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "937642dccf2b16b163b156057b44d71f5867528949d0babb602c3d3c07a7b03b"

  strings:
    $s1 = "|4. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}