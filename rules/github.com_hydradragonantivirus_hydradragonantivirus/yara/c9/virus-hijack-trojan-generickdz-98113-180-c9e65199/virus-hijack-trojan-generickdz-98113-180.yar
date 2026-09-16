rule Virus_Hijack_Trojan_GenericKDZ_98113_180 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_180.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "89223969b4f61e9ec95e8dc214e9197789f4dc8732fafb413a799bafd8b14c90"

  strings:
    $s1 = "d4. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}