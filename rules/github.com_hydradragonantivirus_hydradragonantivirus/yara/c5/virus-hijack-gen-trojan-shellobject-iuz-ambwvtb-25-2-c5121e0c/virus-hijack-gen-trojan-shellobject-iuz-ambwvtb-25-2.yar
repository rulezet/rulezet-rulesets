rule Virus_Hijack_Gen_Trojan_ShellObject_iuZ_amBwvTb_25_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.iuZ@amBwvTb_25_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "83d3b04bc6e49448e1fc362c6beebe9865c6240cb0359f0a7091c61310f3092b"

  strings:
    $s1 = "Copyright 2020 Google LLC. All rights reserved." fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}