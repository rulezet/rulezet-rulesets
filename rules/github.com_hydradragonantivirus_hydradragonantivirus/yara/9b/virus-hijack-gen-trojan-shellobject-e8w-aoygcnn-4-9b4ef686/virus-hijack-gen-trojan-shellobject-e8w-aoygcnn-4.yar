rule Virus_Hijack_Gen_Trojan_ShellObject_e8W_aOygCnn_4 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.e8W@aOygCnn_4.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f2be4022450a6d232d1f54ee3525acfea9a264868984ea528c24df8dccb164e7"

  strings:
    $s1 = "]hundred euros) in all purchase orders transacted" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}