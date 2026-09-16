rule Virus_Hijack_Gen_Trojan_ShellObject_fWW_a0tiwSg_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.fWW@a0tiwSg_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "76b6f685dca8596327d99b38fda9eeb6e548dd657969a4cf8fc6fc22f6680b71"

  strings:
    $s1 = "qThis agreement is governed by the substantive and procedural laws of Ireland without reference to its conflictof laws principle" ascii
    $s2 = "qThis agreement is governed by the substantive and procedural laws of Ireland without reference to its conflictof laws principle" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}