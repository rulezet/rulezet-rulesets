rule Virus_Hijack_Trojan_GenericKDZ_98113_270 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_270.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2adfdd8db6d0c2600cf43d1fa3897a00d8cdb102ee3bbd6149da51fd776fd093"

  strings:
    $s1 = "6k4. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}