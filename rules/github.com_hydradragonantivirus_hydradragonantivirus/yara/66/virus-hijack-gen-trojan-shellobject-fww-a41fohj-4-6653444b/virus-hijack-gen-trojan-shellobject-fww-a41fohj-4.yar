rule Virus_Hijack_Gen_Trojan_ShellObject_fWW_a41FOHj_4 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.fWW@a41FOHj_4.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "78816456e1a550fc1ae0cb3f62c3eeceb69204f300bbb26d983327f2ba41a2d9"

  strings:
    $s1 = "<9(including the denial or cancellation of any export or other license); other event outside the reasonable control of the oblig" ascii
    $s2 = "<9(including the denial or cancellation of any export or other license); other event outside the reasonable control of the oblig" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}