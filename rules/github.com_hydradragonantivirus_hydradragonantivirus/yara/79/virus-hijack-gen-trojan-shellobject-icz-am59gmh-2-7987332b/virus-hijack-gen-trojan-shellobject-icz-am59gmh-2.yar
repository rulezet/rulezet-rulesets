rule Virus_Hijack_Gen_Trojan_ShellObject_iCZ_am59Gmh_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.iCZ@am59Gmh_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "788bce2472dd1b4dbc991ebb4be12d984bb61d0b0d2d38da938318fb28a9c8af"

  strings:
    $s1 = "L@oDyL" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}