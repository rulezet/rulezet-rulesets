rule Virus_Hijack_Gen_Trojan_ShellObject_f8W_aKzODno_15_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f8W@aKzODno_15_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0aa442adc53bf78bcbb1a9110ca74777eb7fed434e37f98945848a9d1f0279b9"

  strings:
    $s1 = "LEvo>." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}