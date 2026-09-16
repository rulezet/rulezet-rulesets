rule Virus_Hijack_Gen_Trojan_ShellObject_g8W_aWD2a0g {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8W@aWD2a0g.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ffc739d3ad13e7d4e3e824a64234348b542aa25fefa47d5e4da4586c0ec15a8e"

  strings:
    $s1 = "\"tINt#" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}