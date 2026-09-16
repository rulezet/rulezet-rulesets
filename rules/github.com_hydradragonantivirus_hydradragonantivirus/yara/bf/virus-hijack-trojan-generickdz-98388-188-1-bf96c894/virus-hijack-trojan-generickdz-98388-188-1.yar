rule Virus_Hijack_Trojan_GenericKDZ_98388_188_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98388_188_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "92a4d96db5ddb505574b567355ea966f349ed8242cb2ca3a7052de896623fd7e"

  strings:
    $s1 = "4X@?gENE" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}