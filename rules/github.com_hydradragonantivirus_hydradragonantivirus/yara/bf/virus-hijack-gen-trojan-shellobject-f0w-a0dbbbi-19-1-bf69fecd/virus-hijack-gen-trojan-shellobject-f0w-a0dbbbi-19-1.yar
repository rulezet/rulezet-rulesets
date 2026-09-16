rule Virus_Hijack_Gen_Trojan_ShellObject_f0W_a0DbbBi_19_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f0W@a0DbbBi_19_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c1c1c918b6c628fdfc43a99dbe46750d36923c90116a34aa8361199a2c04c6ea"

  strings:
    $s1 = "Supreme" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}