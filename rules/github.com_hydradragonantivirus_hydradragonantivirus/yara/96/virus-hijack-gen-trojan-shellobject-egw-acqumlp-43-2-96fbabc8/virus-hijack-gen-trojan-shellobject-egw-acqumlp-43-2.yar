rule Virus_Hijack_Gen_Trojan_ShellObject_eGW_aCQuMlp_43_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.eGW@aCQuMlp_43_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "58df7b839d34916ebae21d29e997af3a6cd00de0c939402202467a247bfed6fd"

  strings:
    $s1 = "Q * FROM" fullword ascii
    $s2 = "Menu@O#" fullword ascii
    $s3 = "echo Y|s}h6P" fullword ascii
    $s4 = "#BOUNDARY#\"W,`" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}