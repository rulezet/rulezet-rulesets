rule Virus_Hijack_Trojan_GenericKDZ_103285_585_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_585_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cdc52f51b4813c3a6baf277f661773296a888c27195052fdb9990cfd042ad9d8"

  strings:
    $s1 = "Adobe Photoshop3" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}