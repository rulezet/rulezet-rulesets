rule Virus_Hijack_Gen_Trojan_ShellObject_fKX_aeBHSxm_12 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.fKX@aeBHSxm_12.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "978847b5631b6450e76a5a59231e8e60455c3c1eb24a6929a4e1c80c73ef20fd"

  strings:
    $s1 = "UIRE_OLSA_V120103_Def_V122304 Page 1 of 11 " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}