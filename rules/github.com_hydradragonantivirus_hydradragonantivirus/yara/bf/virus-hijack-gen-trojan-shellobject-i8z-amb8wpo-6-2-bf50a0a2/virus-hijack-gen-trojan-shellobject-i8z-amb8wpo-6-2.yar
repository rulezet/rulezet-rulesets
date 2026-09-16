rule Virus_Hijack_Gen_Trojan_ShellObject_i8Z_amB8wPo_6_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.i8Z@amB8wPo_6_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e0a691e5743abf1dbe01c4ecdec43df02556a90f7368d56b20ae7dfdbbdbe5dd"

  strings:
    $s1 = "Office Telemetry Dashboard" fullword wide
    $s2 = "@{Rich" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}