rule Virus_Hijack_Gen_Trojan_ShellObject_gCZ_aCmWGmd_1_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.gCZ@aCmWGmd_1_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "735210187591d2befe1be1544fab2c9b96835a8efe970ed8aa099ddda313a2a4"

  strings:
    $s1 = "Dodderer" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}