rule Virus_Hijack_Gen_Trojan_ShellObject_08Z_auel1S_7 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.08Z@auel1S_7.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2d925baf9f29e1d7b34e5a1dbc1d0d9c53b5075df3a2fa929e1fc340885b02a0"

  strings:
    $s1 = "OSoftware Assurance." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}