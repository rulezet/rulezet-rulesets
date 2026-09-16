rule Virus_Hijack_Gen_Trojan_ShellObject_m0Z_ae3yXvm_7_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.m0Z@ae3yXvm_7_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "39b52356da1f35c5bad343eea8880f4d8bdd6c0228a7a9b85e5f0117c6296287"

  strings:
    $s1 = "TickTock" fullword ascii
    $s2 = "Openresty Tool" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}