rule Virus_Hijack_Gen_Trojan_ShellObject_fWW_a0tiwSg_3 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.fWW@a0tiwSg_3.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c9ea8378b4aa7e96c16c297dc213b1e3135c89588037ffb859794166e5794748"

  strings:
    $s1 = "lThis agreement is governed by the substantive and procedural laws of Ireland without reference to its conflictof laws principle" ascii
    $s2 = "lThis agreement is governed by the substantive and procedural laws of Ireland without reference to its conflictof laws principle" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}