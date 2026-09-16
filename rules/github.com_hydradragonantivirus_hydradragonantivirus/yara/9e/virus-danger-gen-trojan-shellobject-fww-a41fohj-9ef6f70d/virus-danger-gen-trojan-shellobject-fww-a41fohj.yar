rule Virus_Danger_Gen_Trojan_ShellObject_fWW_a41FOHj {
  meta:
    description = "datamaliciousorder - file Virus.Danger_Gen.Trojan.ShellObject.fWW@a41FOHj.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "53f4378eebb3a1b3328601ff5825987274251c0c1e1a7c6766d7fa62d206aa8b"

  strings:
    $s1 = "y0(including the denial or cancellation of any export or other license); other event outside the reasonable control of the oblig" ascii
    $s2 = "y0(including the denial or cancellation of any export or other license); other event outside the reasonable control of the oblig" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}