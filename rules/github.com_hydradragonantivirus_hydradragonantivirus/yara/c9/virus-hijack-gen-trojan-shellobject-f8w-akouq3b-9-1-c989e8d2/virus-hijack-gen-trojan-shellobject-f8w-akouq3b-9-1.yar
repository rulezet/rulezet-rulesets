rule Virus_Hijack_Gen_Trojan_ShellObject_f8W_aKoUq3b_9_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f8W@aKoUq3b_9_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f3df86e607935618b9765c5e80b46150f566470dea24536fa2196dea027ac22a"

  strings:
    $s1 = "return castle" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}