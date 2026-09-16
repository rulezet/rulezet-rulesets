rule Virus_Hijack_Gen_Trojan_ShellObject_gyZ_aag1Gcl_5_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.gyZ@aag1Gcl_5_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2cbc224efa8d40a8d143af85795318e3253474906b7a89e4516bc69976efed16"

  strings:
    $s1 = "Office Telemetry Agent" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}