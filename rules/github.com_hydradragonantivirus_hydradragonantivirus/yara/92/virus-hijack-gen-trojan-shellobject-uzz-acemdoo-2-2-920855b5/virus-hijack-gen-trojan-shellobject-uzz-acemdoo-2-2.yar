rule Virus_Hijack_Gen_Trojan_ShellObject_UzZ_aCEmdoo_2_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.UzZ@aCEmdoo_2_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f5c4dec73b93d8ac6cc3fb6b33ee07cfd62379067107db3d020b099ee361cb7c"

  strings:
    $s1 = "Flicks Training" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}