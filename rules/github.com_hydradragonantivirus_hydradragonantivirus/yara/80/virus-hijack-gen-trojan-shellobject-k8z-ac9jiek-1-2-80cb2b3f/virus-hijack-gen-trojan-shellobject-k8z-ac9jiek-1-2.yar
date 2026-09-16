rule Virus_Hijack_Gen_Trojan_ShellObject_k8Z_aC9JiEk_1_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.k8Z@aC9JiEk_1_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d6df683b43c7b4574817eb3577671d3b82095e26cb8196cbc315f4e089d8ed7c"

  strings:
    $s1 = "laic`k" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}