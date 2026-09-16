rule Virus_Hijack_Gen_Trojan_ShellObject_dyW_auLFnao_22_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.dyW@auLFnao_22_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3adf98d268569ec43777ba82410569877554b3d73e45d5b7aa273cda42a3b363"

  strings:
    $s1 = "aNte\"" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}