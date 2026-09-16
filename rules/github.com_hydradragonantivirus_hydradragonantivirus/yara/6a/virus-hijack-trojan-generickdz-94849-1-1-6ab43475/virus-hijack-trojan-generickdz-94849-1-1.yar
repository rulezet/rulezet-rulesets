rule Virus_Hijack_Trojan_GenericKDZ_94849_1_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.94849_1_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c4efe6d509915d8e2c2f87819817a478b48144853ab6aefce3c94f6fb38477a5"

  strings:
    $s1 = "6i[hEml" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}