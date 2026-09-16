rule Virus_Hijack_Trojan_GenericKDZ_98113_3 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_3.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5e4b01ea163c0bfaae85d493dc6a491610a1e1c1bc83200aaaa12e5c1463a556"

  strings:
    $s1 = "N4. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}