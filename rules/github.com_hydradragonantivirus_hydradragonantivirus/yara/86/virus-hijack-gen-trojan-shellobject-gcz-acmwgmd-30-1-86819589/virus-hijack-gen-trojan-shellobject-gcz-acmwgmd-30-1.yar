rule Virus_Hijack_Gen_Trojan_ShellObject_gCZ_aCmWGmd_30_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.gCZ@aCmWGmd_30_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6bc84ce02711cfb85500c331428332f9becc89b399c85f36dad5eaefd317b333"

  strings:
    $s1 = "Vesicular" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}