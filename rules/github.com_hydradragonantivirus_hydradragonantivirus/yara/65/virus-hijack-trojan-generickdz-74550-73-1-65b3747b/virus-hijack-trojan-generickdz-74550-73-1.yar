rule Virus_Hijack_Trojan_GenericKDZ_74550_73_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.74550_73_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "609ade7d425106fe36417a72822e83e2b52b0d45d8010c33f4af9311ec980d88"

  strings:
    $s1 = "-@meAk" fullword ascii
    $s2 = "C?RANd" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}