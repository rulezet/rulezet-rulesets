rule Virus_Hijack_Gen_Trojan_ShellObject_fWW_a41FOHj_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.fWW@a41FOHj_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0b35e0e76f7ada3633425e4273f180b687390a9e59cccfcb7734453bacb6a3ba"

  strings:
    $s1 = "'(including the denial or cancellation of any export or other license); other event outside the reasonable control of the obliga" ascii
    $s2 = "'(including the denial or cancellation of any export or other license); other event outside the reasonable control of the obliga" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}