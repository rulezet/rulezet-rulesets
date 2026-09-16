rule Virus_Hijack_Gen_Trojan_ShellObject_f8W_aKoUq3b_24_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f8W@aKoUq3b_24_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "33cfa8f25ef046e0618318dc676ce598ddf63037c8f9a14ac5883213c1649588"

  strings:
    $s1 = "On&Rich" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}