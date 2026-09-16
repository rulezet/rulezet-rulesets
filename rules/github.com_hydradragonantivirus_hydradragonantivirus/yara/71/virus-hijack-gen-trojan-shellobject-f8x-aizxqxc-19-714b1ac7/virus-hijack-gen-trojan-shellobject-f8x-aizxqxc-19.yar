rule Virus_Hijack_Gen_Trojan_ShellObject_f8X_aiZXqXc_19 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f8X@aiZXqXc_19.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "015e26e9b8fa96166b78540457d9af35781f2f57df06f65e44d733cb87b1141f"

  strings:
    $s1 = "5PProfessional User: is defined as an individual authorized by you to use the application programs which are installed on a" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}