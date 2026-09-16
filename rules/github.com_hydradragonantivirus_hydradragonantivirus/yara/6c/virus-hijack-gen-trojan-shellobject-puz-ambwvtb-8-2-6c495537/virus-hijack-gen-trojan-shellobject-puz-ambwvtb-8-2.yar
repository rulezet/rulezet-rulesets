rule Virus_Hijack_Gen_Trojan_ShellObject_PuZ_amBwvTb_8_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.PuZ@amBwvTb_8_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "674dc8eec0ad265387e8b19fb931f432adec044a0b5690d8b5b6749358f4b1f9"

  strings:
    $s1 = "h>SuDs" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}