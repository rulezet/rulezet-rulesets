rule Virus_Hijack_Gen_Trojan_ShellObject_f8X_aiZXqXc_17 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f8X@aiZXqXc_17.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bf14b0108bd6bec6beba4e30327dd270cd99b0b463ddffdb0fdfa181231acaf8"

  strings:
    $s1 = "3Professional User: is defined as an individual authorized by you to use the application programs which are installed on a" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}