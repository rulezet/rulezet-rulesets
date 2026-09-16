rule Virus_Hijack_Trojan_GenericKDZ_103545_31_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103545_31_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "157cfa2ee31e8b6cf4ac3c5647b1c4881d3f3bfa31dbc7670422ea81f84db48a"

  strings:
    $s1 = "Ik-QjZ$fisC" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}