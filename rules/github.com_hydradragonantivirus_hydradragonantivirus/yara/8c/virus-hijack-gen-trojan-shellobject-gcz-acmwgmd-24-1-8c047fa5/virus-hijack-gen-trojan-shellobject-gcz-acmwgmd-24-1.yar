rule Virus_Hijack_Gen_Trojan_ShellObject_gCZ_aCmWGmd_24_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.gCZ@aCmWGmd_24_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "534c393054ba3de256e5e495c53a1bac216fa7562feed56cf71d89b9025b8257"

  strings:
    $s1 = "Molecast" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}