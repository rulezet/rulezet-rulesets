rule Virus_Hijack_Gen_Trojan_ShellObject_gyZ_aO_sVhl_9_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.gyZ@aO@sVhl_9_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7d075ea4df919b1c0b301242405d965eda349d64fe85e30d7cdbd4d1f182bb62"

  strings:
    $s1 = "Office Telemetry Agent" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}