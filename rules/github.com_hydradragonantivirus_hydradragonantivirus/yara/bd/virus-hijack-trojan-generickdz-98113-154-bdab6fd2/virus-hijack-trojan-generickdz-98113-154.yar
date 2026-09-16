rule Virus_Hijack_Trojan_GenericKDZ_98113_154 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_154.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c2cc3062547f606cde60e44f4488059455f59562620e39941a0adc27b96fd4f0"

  strings:
    $s1 = "[4. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}