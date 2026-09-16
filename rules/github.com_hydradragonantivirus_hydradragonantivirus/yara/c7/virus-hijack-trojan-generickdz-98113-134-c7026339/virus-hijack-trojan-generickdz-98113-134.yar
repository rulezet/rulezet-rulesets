rule Virus_Hijack_Trojan_GenericKDZ_98113_134 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_134.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8f0ef7b8553c81111e9e67a38e95ef0c8e008e6bbf681cc8c845a97c0e42afe8"

  strings:
    $s1 = "Z4. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}