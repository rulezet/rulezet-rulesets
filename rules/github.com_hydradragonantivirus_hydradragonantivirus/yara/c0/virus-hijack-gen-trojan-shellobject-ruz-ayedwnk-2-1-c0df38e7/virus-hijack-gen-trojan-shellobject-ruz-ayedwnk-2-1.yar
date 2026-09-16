rule Virus_Hijack_Gen_Trojan_ShellObject_ruZ_ayeDwnk_2_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.ruZ@ayeDwnk_2_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "219cb83035600eafcefa4bf3a3b64fd8187b4780cc7b57f1c2f44d539bf8f8a0"

  strings:
    $s1 = "(soLE`8SF" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}