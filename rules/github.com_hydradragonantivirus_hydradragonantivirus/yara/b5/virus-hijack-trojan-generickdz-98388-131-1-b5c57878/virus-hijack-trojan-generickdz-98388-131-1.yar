rule Virus_Hijack_Trojan_GenericKDZ_98388_131_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98388_131_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "83f89b3dfbad042536922a54f5973669a93550aeac11e8064b0b83de81a017fd"

  strings:
    $s1 = "PeoN&]" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}