rule Virus_Hijack_Gen_Trojan_ShellObject_g8X_aK5_lZo_7_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8X@aK5!lZo_7_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2a3b49a3fa70f30ddbbc9d8c51291c87317bf4aabe05f44c182dac9612380b89"

  strings:
    $s1 = "Adipic" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}