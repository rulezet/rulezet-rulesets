rule Virus_Hijack_Gen_Trojan_ShellObject_gCZ_aCmWGmd_29_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.gCZ@aCmWGmd_29_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b321c11382b38b4b80488e530a13b1b32b81e9ef297bec10cc7bbbf6a8b8485b"

  strings:
    $s1 = "Franking" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}