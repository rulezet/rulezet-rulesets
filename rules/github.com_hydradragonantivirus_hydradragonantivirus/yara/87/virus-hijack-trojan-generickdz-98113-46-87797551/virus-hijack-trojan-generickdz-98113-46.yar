rule Virus_Hijack_Trojan_GenericKDZ_98113_46 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_46.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "76ef49728b2095f6f8b27f6b1755b94302141819104545becb3f1b10544f787e"

  strings:
    $s1 = "34. Language Packs and Proofing Tools. If you acq" fullword ascii
    $s2 = "taXI?GX" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}