rule Virus_Hijack_Trojan_GenericKDZ_98113_344 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_344.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e846314c70976825579cbd1c98f7fe658e7f4723e9fc3f12e61a4d50d8c9809b"

  strings:
    $s1 = ",4. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}