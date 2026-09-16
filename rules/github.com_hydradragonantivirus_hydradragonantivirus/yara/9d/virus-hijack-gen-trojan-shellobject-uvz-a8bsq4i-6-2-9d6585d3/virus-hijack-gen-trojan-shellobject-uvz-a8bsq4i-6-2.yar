rule Virus_Hijack_Gen_Trojan_ShellObject_uvZ_a8bSq4i_6_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.uvZ@a8bSq4i_6_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "14e9d3024759ead0f15e254c66002a8f335f1c8ba5844469de4ba3509aae68aa"

  strings:
    $s1 = "Copyright 2020 Google LLC. All rights reserved." fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}