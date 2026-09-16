rule Virus_Hijack_Gen_Trojan_ShellObject_PCZ_aSQ1jei_4_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.PCZ@aSQ1jei_4_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "11930b40907b5ac4fb4c2e8d7f53fe1f1c8e18d7b16baa3ea7bb98e29e69111f"

  strings:
    $s1 = "BEEN{6y" fullword ascii
    $s2 = ")suPE@A" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}