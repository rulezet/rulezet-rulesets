rule Virus_Danger_Generic_Dacic_902B1FCB_A_4F297082_1 {
  meta:
    description = "datamaliciousorder - file Virus.Danger_Generic.Dacic.902B1FCB.A.4F297082_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5f59890be1be61ea737861fa4522f42020f2f49e80e9253d7580a9efa1fdfbc7"

  strings:
    $s1 = "Event Viewer.lnk" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}