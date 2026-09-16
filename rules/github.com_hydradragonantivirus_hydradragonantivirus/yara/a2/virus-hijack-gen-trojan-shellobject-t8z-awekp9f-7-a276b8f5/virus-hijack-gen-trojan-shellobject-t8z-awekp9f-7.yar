rule Virus_Hijack_Gen_Trojan_ShellObject_t8Z_aWEkp9f_7 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.t8Z@aWEkp9f_7.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "05b029ca490deb0c8c2cf8a5b60d9dfe2abdc8246b34e3766eb1f03af54a70c8"

  strings:
    $s1 = "?IRE_OLSA_V120103_Def_V122304 Page 7 of 11 " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}