rule Virus_Hijack_Gen_Trojan_ShellObject_i8Z_aO3hPGn_7 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.i8Z@aO3hPGn_7.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f01a758874c23c3cc07e41a10a5df0249dd1b4efe870de086b6b0a64fa906543"

  strings:
    $s1 = "fProfessional User: is defined as an individual authorized by you to use the application programs which are installed on a" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}