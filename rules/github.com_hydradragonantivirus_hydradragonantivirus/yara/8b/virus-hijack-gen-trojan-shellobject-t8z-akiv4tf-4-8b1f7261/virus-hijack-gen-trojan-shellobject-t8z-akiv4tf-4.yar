rule Virus_Hijack_Gen_Trojan_ShellObject_t8Z_aKiV4Tf_4 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.t8Z@aKiV4Tf_4.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dea8a7b797edd5afbd65337f05f8032cb7809c96b59c081838a4c86b0f0ee8b4"

  strings:
    $s1 = "tvirtualization, see the Additional Terms." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}