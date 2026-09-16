rule Virus_Hijack_Gen_Trojan_ShellObject_dCW_aGhujNi_43_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.dCW@aGhujNi_43_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6663470128cff7738045941c53937b8c7cc6e2deeac16e97abdd8fbf8030b63c"

  strings:
    $s1 = "pOnG'J" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}