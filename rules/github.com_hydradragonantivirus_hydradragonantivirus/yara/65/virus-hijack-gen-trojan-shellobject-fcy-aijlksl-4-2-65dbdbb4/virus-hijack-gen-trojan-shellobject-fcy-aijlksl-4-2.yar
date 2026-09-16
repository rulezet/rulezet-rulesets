rule Virus_Hijack_Gen_Trojan_ShellObject_fCY_aijlKSl_4_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.fCY@aijlKSl_4_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "08f3f460ee90e6b776d463743d67c8a8514bdc778583a4f0b4a25989f08e455e"

  strings:
    $s1 = "7-Zip 18.06 (x86) : Copyright (c) 1999-2018 Igor Pavlov : 2018-12-30" fullword ascii
    $s2 = "  @listfile : set path to listfile that contains file names" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}