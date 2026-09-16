rule Virus_Hijack_Trojan_GenericKDZ_98113_139_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_139_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a61000e0e4408f5decc8dbc87ccda8bc442a88e621335576ba2fbc6548dc73ed"

  strings:
    $s1 = "Tn%HiSt" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}