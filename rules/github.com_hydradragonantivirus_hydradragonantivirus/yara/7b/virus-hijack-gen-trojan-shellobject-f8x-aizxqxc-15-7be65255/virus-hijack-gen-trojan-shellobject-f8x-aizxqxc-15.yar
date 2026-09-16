rule Virus_Hijack_Gen_Trojan_ShellObject_f8X_aiZXqXc_15 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f8X@aiZXqXc_15.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3b1c7d7fe948dd2e19579d43ceb198699e8c91e25d69e1c17cc2ff6437658496"

  strings:
    $s1 = "2aProfessional User: is defined as an individual authorized by you to use the application programs which are installed on a" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}