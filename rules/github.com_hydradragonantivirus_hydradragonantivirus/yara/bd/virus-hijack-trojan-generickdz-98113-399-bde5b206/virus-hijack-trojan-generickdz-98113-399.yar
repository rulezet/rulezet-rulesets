rule Virus_Hijack_Trojan_GenericKDZ_98113_399 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_399.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a26b35bc8eb0d4528772f29efa82f30df0ffc766a32816cc95a7c279add21987"

  strings:
    $s1 = "q4. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}