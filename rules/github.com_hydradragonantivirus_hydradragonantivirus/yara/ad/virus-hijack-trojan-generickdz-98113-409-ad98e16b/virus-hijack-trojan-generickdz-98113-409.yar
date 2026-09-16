rule Virus_Hijack_Trojan_GenericKDZ_98113_409 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_409.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4aa702ec67d23064db638c08920d3149a7018545efa7a9f2d4e980671f5a1e6c"

  strings:
    $s1 = "k4. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}