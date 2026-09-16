rule Virus_Hijack_Gen_Trojan_ShellObject_ruZ_aGV9gJb_7_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.ruZ@aGV9gJb_7_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "14aadd224d36746f5caab0ca5aca23a1acd1549d87f974512d152ce191065c99"

  strings:
    $s1 = "BIT COMPUTER CO., LTD.0" fullword ascii
    $s2 = "BIT COMPUTER CO., LTD.1" fullword ascii
    $s3 = "Action@QA" fullword ascii
    $s4 = "Font<ZC" fullword ascii
    $s5 = "Management Team10" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}