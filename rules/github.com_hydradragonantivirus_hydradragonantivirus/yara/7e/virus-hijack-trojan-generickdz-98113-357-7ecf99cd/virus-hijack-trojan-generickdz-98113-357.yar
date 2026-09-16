rule Virus_Hijack_Trojan_GenericKDZ_98113_357 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_357.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0d063f9698667f562c77ef9872e45087f95a2ee122cd951e1c59d41e2cb3b2ff"

  strings:
    $s1 = "V4. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}