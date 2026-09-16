rule Virus_Hijack_Gen_Trojan_ShellObject_g8W_a4IIY9p_5_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8W@a4IIY9p_5_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "51cf9c360b95a95e7312f09f226bbb19524dd0d58c295c42c9834c959be0c10d"

  strings:
    $s1 = "WEED{*" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}