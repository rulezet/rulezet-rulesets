rule Virus_Hijack_Gen_Trojan_ShellObject_t8Z_aWEkp9f_6 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.t8Z@aWEkp9f_6.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1dc90dd989fc153a008890b982f144604f83b7795fc1bd0ea065b32c58934874"

  strings:
    $s1 = "?IRE_OLSA_V120103_Def_V122304 Page 7 of 11 " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}