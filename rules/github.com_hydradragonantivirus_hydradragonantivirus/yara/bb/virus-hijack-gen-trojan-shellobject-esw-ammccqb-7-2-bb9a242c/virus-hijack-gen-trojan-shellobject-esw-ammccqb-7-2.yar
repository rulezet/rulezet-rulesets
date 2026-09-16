rule Virus_Hijack_Gen_Trojan_ShellObject_eSW_amMcCQb_7_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.eSW@amMcCQb_7_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "29eaddd63fd7e64b4d28bef2fd98752d1153d386b7269d91700712b36c264cbb"

  strings:
    $s1 = "drawling" fullword wide
    $s2 = "cliffy" fullword wide
    $s3 = "repast's" fullword wide
    $s4 = "MUTELY" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}