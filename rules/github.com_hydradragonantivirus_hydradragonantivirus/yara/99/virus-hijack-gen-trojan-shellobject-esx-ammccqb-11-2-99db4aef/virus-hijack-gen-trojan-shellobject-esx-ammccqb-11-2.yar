rule Virus_Hijack_Gen_Trojan_ShellObject_eSX_amMcCQb_11_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.eSX@amMcCQb_11_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "85843f629a4a1a88b39b77263084289e3cb857c26e6751e8dbae764e1c25cfa3"

  strings:
    $s1 = "6Kunming Shuangyinqing Science and Technology Co., Ltd.1?0=" fullword ascii
    $s2 = "6Kunming Shuangyinqing Science and Technology Co., Ltd.0" fullword ascii
    $s3 = "Rich?!" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}