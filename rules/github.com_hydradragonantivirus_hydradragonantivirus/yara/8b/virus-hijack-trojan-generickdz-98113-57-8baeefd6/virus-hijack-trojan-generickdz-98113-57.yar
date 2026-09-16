rule Virus_Hijack_Trojan_GenericKDZ_98113_57 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_57.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "18567bb391fdef6616ce72e77fe8eb592ef71a6ca318684db5b8d085db480e07"

  strings:
    $s1 = "N,4. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}