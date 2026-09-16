rule Virus_Hijack_Gen_Trojan_ShellObject_PCZ_aSQ1jei_3_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.PCZ@aSQ1jei_3_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cd0cf97a7334202b8af53746f1ffa935acc9016d9c84d02e5c11944993540e84"

  strings:
    $s1 = "- hEME" fullword ascii
    $s2 = "mItE!>R" fullword ascii
    $s3 = "\\\"piCk" fullword ascii
    $s4 = ":]sCYE" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}