rule Virus_Hijack_Gen_Trojan_ShellObject_f8W_aKzODno_11_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f8W@aKzODno_11_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "81cbcfda0c5f5de1dac4f9f0e4ce22fe956c78ebefe2898f455ae68fe6f2e870"

  strings:
    $s1 = "return castle" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}