rule Virus_Hijack_Gen_Trojan_ShellObject_dCW_aGhujNi_22_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.dCW@aGhujNi_22_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cba63a7f8c1029a8264121b62f0e64e46b47b3070935c0fc1f0f7554f575e418"

  strings:
    $s1 = "t;WAre" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}