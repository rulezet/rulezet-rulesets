rule Virus_Danger_Gen_Trojan_ShellObject_f8X_aiZXqXc_1 {
  meta:
    description = "datamaliciousorder - file Virus.Danger_Gen.Trojan.ShellObject.f8X@aiZXqXc_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "96dd70362bc4da87a392ba176dce79cd210942dcd1c160047a4355405f8d133c"

  strings:
    $s1 = "55Professional User: is defined as an individual authorized by you to use the application programs which are installed on a" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}