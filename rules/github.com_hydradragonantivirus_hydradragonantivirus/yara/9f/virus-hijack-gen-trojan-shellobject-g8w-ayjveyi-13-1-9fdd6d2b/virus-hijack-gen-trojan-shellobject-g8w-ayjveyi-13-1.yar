rule Virus_Hijack_Gen_Trojan_ShellObject_g8W_ayJVeyi_13_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8W@ayJVeyi_13_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f93a024dc73e24b76c5442cd62e9334d3d3a9b27626b7402ca2a9f3bcc0df74b"

  strings:
    $s1 = "Gramophone" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}