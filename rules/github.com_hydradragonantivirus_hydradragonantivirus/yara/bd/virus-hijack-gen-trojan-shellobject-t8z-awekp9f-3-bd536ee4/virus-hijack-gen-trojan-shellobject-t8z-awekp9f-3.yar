rule Virus_Hijack_Gen_Trojan_ShellObject_t8Z_aWEkp9f_3 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.t8Z@aWEkp9f_3.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6d3ae2b268b0455e5940a7f59ef8d1efe8983c86e2648aed90968df9cc656d2a"

  strings:
    $s1 = "]IRE_OLSA_V120103_Def_V122304 Page 7 of 11 " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}