rule Virus_Hijack_Gen_Trojan_ShellObject_h8W_aqG68Ic_6_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.h8W@aqG68Ic_6_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8da9944952289d19ec7542d2acddb51f579fa3b2fb51fea32837e09c0981c585"

  strings:
    $s1 = "Versus" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}