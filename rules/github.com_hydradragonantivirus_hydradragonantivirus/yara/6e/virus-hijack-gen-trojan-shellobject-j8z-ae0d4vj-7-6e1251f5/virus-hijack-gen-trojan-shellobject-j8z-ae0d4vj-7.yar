rule Virus_Hijack_Gen_Trojan_ShellObject_j8Z_ae0D4Vj_7 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.j8Z@ae0D4Vj_7.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "641f69bed06390c96a50317699b093e795a73f1906ddcf976404a04a644cb131"

  strings:
    $s1 = " ca neutral arbitrator, whose decision will be final except for a limited right of appeal under the Federal" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}