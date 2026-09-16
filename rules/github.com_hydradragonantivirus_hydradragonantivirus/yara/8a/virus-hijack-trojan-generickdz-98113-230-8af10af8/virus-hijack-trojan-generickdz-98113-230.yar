rule Virus_Hijack_Trojan_GenericKDZ_98113_230 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_230.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "efd7a5203d1477504f46366f26d5f795a0cd1257a9e79a8b2e19bc8e92a83ec1"

  strings:
    $s1 = "d{4. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}