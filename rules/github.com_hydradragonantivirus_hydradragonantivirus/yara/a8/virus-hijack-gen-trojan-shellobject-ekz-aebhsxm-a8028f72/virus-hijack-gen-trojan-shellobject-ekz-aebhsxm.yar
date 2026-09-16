rule Virus_Hijack_Gen_Trojan_ShellObject_EKZ_aeBHSxm {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.EKZ@aeBHSxm.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d55911e16e4e820b90e933cc8de3f2b06e766b1adaec51eadd04245a0e0bfa27"

  strings:
    $s1 = "?}IRE_OLSA_V120103_Def_V122304 Page 1 of 11 " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}