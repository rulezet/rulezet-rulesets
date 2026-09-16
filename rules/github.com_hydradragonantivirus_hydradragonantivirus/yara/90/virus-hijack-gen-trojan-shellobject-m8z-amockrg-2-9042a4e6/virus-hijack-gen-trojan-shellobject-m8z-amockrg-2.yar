rule Virus_Hijack_Gen_Trojan_ShellObject_m8Z_amOckRg_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.m8Z@amOckRg_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "01ad9a1fb7bd4c20116e873373c84169b23bcd3d44696f223f95f9a4d2eff95d"

  strings:
    $s1 = "assets, owned or managed for others, which were " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}