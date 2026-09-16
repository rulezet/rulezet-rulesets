rule Virus_Hijack_Gen_Trojan_ShellObject_f4W_aixDqOn_1_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f4W@aixDqOn_1_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dc38b36a4814ad0ea0fa056a8fb08a0f2d2f841b161f18e47ce2d5eb8d6d1dce"

  strings:
    $s1 = "*sAiR@" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}