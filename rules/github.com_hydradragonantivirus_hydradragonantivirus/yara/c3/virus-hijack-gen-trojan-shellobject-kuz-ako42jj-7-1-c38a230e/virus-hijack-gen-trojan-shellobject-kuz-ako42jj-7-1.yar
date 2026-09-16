rule Virus_Hijack_Gen_Trojan_ShellObject_KuZ_aKo42Jj_7_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.KuZ@aKo42Jj_7_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "701eba379154907296763a599db9b09ab0ccf7549be0b0ddcd82fd8c28b3a5c0"

  strings:
    $s1 = "soft Visual StudQn" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}