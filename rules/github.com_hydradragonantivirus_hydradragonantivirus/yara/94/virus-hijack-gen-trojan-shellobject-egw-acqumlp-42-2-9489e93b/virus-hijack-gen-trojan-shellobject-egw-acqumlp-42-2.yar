rule Virus_Hijack_Gen_Trojan_ShellObject_eGW_aCQuMlp_42_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.eGW@aCQuMlp_42_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5d1bc497acc79b17df9308615ea07621d3d25454cbc2e121f60ce2af9922d3a8"

  strings:
    $s1 = "Q * FROM" fullword ascii
    $s2 = "Menu@O#" fullword ascii
    $s3 = "echo Y|s}h6P" fullword ascii
    $s4 = "#BOUNDARY#\"W,`" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}