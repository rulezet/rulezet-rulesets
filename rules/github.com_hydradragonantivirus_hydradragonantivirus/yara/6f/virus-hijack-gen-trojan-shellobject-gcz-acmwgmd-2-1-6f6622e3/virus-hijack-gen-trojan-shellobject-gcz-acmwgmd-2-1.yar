rule Virus_Hijack_Gen_Trojan_ShellObject_gCZ_aCmWGmd_2_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.gCZ@aCmWGmd_2_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e813acc33768d4a6d453cd02ab10f4a5521d9c171b316269373e5702d98c7b06"

  strings:
    $s1 = "Palmed" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}