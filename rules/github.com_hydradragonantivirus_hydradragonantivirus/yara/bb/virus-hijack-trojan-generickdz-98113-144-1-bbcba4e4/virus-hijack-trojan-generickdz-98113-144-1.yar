rule Virus_Hijack_Trojan_GenericKDZ_98113_144_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_144_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "412092f6b525444285a7e8fd5bad79325020dc1d83080d528ebd088cfc3fa38a"

  strings:
    $s1 = "]+!#U`hazY" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}