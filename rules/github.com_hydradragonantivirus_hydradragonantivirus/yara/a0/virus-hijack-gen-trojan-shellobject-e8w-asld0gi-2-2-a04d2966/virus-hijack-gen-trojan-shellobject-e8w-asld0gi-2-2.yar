rule Virus_Hijack_Gen_Trojan_ShellObject_e8W_aSLD0Gi_2_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.e8W@aSLD0Gi_2_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "13c74d1558c02500797b0faa99f7818cc45e4b94c343f79ca82c43ea94766c6c"

  strings:
    $s1 = "KeyLog Attachment" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}