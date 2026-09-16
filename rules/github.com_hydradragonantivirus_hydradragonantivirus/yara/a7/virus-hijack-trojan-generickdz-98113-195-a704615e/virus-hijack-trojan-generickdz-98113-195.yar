rule Virus_Hijack_Trojan_GenericKDZ_98113_195 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_195.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "24624554b064660660403fa75f2ad42c2c6cebc31fda2930e5ffacf506ba9a01"

  strings:
    $s1 = "Q4. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}