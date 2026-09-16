rule Virus_Hijack_Gen_Trojan_ShellObject_fWW_a41FOHj_16 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.fWW@a41FOHj_16.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cb83fc9743e1a1f4cc21cab986e66a3801ee635b4b34782987a8a349661f1304"

  strings:
    $s1 = "9(including the denial or cancellation of any export or other license); other event outside the reasonable control of the obliga" ascii
    $s2 = "9(including the denial or cancellation of any export or other license); other event outside the reasonable control of the obliga" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}