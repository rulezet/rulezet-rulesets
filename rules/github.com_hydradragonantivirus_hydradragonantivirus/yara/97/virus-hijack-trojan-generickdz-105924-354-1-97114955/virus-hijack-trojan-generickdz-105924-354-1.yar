rule Virus_Hijack_Trojan_GenericKDZ_105924_354_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_354_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "024b1ea04903fdda9fe39bdaa99bf4038589fac52ece694c4befccdd5af461ab"

  strings:
    $s1 = "\"pika " fullword ascii
    $s2 = "G^?vOTa" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}