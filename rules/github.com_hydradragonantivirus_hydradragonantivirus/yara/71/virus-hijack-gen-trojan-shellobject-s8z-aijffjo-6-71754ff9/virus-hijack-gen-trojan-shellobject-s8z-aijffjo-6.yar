rule Virus_Hijack_Gen_Trojan_ShellObject_s8Z_aiJFfJo_6 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.s8Z@aiJFfJo_6.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "239aecb10c71788cdc707e73705874f899374a693cd08c25ee3cb266b4161886"

  strings:
    $s1 = "you to install only one copy of the `" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}