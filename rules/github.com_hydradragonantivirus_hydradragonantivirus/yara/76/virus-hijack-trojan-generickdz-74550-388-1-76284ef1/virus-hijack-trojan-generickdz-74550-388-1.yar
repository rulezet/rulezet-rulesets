rule Virus_Hijack_Trojan_GenericKDZ_74550_388_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.74550_388_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9bffe286f0d466b495edf33732d3e69370744d3f4163a79cf50e8732bf236ab5"

  strings:
    $s1 = "%rANN)T" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}