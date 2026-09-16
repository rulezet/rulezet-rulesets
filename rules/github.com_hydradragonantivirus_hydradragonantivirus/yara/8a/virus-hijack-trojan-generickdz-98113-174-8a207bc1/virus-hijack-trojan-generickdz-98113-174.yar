rule Virus_Hijack_Trojan_GenericKDZ_98113_174 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_174.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "97e4110422a84f30de3bdd4592e039287f49c04d79323c29337ba87c7599155a"

  strings:
    $s1 = "M4. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}