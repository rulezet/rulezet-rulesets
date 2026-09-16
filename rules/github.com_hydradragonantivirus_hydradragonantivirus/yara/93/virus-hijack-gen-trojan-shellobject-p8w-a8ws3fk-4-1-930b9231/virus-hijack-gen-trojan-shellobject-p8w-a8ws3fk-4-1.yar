rule Virus_Hijack_Gen_Trojan_ShellObject_p8W_a8ws3Fk_4_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.p8W@a8ws3Fk_4_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8a73c7fc2f4f0f1b726daef88a658c96ced2372c1f80962463fb577a2667de33"

  strings:
    $s1 = "Interner Explorer" fullword wide
    $s2 = "serOon" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}