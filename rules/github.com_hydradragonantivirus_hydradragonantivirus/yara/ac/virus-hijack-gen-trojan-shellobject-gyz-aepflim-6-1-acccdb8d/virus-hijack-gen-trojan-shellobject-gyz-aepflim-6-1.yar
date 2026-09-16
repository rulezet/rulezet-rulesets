rule Virus_Hijack_Gen_Trojan_ShellObject_gyZ_aepfLIm_6_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.gyZ@aepfLIm_6_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "54676bdb7299818b7a79fbe1c7ca2e590f2e5a693b628c069d4bab7f545734cd"

  strings:
    $s1 = "Verdured" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}