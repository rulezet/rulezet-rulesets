rule Virus_Hijack_Trojan_GenericKDZ_98113_237 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_237.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b09095f3227cb2c8850f496819358c6e501fe8795649e83131a0c69ed171c595"

  strings:
    $s1 = "LF4. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}