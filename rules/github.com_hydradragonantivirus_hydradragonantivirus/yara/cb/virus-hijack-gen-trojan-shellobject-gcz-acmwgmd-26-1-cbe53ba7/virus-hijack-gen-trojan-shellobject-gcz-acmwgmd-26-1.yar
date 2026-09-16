rule Virus_Hijack_Gen_Trojan_ShellObject_gCZ_aCmWGmd_26_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.gCZ@aCmWGmd_26_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "40e716422dfc0896f3c9030071bd79fa18696506b35404fb8790340ad8bda72c"

  strings:
    $s1 = "Susceptor" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}