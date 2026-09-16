rule Virus_Hijack_Gen_Trojan_ShellObject_gyY_aWevApi_15_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.gyY@aWevApi_15_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bf847926d36df4f365a0f4c05e269d669ff6b86fb1de03316abf1950b32521d3"

  strings:
    $s1 = "Derringer" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}