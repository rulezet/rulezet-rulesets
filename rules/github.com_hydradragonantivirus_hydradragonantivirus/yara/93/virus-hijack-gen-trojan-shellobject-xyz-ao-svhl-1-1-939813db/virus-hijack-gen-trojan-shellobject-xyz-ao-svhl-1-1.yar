rule Virus_Hijack_Gen_Trojan_ShellObject_xyZ_aO_sVhl_1_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.xyZ@aO@sVhl_1_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "62a2fbcf4caedaaa58a90967fcb3f52b5592f529e4817be1258126bf0fb5f1da"

  strings:
    $s1 = ",Reference Viewing Con" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}