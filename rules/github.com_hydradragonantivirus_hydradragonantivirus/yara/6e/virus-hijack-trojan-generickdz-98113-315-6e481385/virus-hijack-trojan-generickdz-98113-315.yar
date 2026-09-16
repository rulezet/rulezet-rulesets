rule Virus_Hijack_Trojan_GenericKDZ_98113_315 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_315.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "69f4ecc153dce515b27de3137a3ba7fb2a753b7673f442cbfe48f670a5253b13"

  strings:
    $s1 = "o4. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}