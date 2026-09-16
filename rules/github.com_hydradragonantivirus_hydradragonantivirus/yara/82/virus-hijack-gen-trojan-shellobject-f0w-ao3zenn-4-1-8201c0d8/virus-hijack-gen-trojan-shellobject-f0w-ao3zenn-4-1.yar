rule Virus_Hijack_Gen_Trojan_ShellObject_f0W_aO3zEnn_4_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f0W@aO3zEnn_4_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6f0388ee18851963edc2cce59cb4c890437c3b9a9dd33619811a14eedb17e068"

  strings:
    $s1 = "AudMig: No audio endpoint migration settings found 0x2" fullword ascii
    $s2 = "***AudMig: No audio endpoint migration settings found 0x2" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}