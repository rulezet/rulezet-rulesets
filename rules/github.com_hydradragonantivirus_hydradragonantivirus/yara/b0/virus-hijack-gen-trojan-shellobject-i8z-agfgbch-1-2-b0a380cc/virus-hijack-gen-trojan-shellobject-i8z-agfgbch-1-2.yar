rule Virus_Hijack_Gen_Trojan_ShellObject_i8Z_aGFgBch_1_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.i8Z@aGFgBch_1_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "acbf2774ee7f8d049b8c742a69a3ce74a65dcd5f2bb2831425d8112f0f9e873c"

  strings:
    $s1 = "5.0.6 @Commit: 478b2f8c0e480665f6c52c95cd57830784dc9560" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}