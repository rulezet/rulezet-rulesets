rule Virus_Hijack_Gen_Trojan_ShellObject_e8W_a8TFxTj_10 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.e8W@a8TFxTj_10.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b4821c679010869b2801d983e8d5931b28c5f88ac127db062e33beaaa507e988"

  strings:
    $s1 = "LITE#V" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}