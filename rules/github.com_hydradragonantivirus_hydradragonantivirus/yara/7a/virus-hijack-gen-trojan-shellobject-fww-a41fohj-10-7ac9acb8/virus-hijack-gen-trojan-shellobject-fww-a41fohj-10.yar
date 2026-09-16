rule Virus_Hijack_Gen_Trojan_ShellObject_fWW_a41FOHj_10 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.fWW@a41FOHj_10.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "de07e74ffedbd7b96696e635a6ea744dc0c31a785e1ca68457b5c449ebc1b61b"

  strings:
    $s1 = "w(including the denial or cancellation of any export or other license); other event outside the reasonable control of the obliga" ascii
    $s2 = "w(including the denial or cancellation of any export or other license); other event outside the reasonable control of the obliga" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}