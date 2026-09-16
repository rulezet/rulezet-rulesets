rule Trojan_Autorun_Gen_Trojan_Backdoor2_kmX_aiKUf7lb_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Gen.Trojan.Backdoor2.kmX@aiKUf7lb_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1242dd8cd4906d0e69941f8e884118997a1624850a9df7b1982976e9427975db"

  strings:
    $s1 = "SErO;E" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}