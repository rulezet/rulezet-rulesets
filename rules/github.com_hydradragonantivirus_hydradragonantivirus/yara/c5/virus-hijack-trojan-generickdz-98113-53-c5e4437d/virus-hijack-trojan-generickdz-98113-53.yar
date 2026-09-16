rule Virus_Hijack_Trojan_GenericKDZ_98113_53 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_53.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "185a00b5a89af201def4baa8f8156b4861abe948c2198f5a171a3e43db6a9717"

  strings:
    $s1 = "84. Language Packs and Proofing Tools. If you acq" fullword ascii
    $s2 = "seaR*QaR" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}