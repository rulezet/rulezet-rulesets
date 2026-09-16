rule Virus_Hijack_Gen_Trojan_ShellObject_l8Z_aKTibuk_1_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.l8Z@aKTibuk_1_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f163b8705e4f9d11974400b20e9a14eeff4a875da3981eaded90d3fde2484df0"

  strings:
    $s1 = "Win Interactive LLC* Right" fullword wide
    $s2 = "2014 Win Interactive LLC* Right, Inc. All Rights Reserved" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}