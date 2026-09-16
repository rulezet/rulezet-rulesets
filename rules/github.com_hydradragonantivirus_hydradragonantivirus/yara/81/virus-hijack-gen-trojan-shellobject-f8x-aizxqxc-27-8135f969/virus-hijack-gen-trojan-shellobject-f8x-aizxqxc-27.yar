rule Virus_Hijack_Gen_Trojan_ShellObject_f8X_aiZXqXc_27 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f8X@aiZXqXc_27.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a4e56c86f76c47e07d42f48e6ce01b5d75d493b4e116c1f86cc636a9e42a2f7c"

  strings:
    $s1 = "HProfessional User: is defined as an individual authorized by you to use the application programs which are installed on a" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}