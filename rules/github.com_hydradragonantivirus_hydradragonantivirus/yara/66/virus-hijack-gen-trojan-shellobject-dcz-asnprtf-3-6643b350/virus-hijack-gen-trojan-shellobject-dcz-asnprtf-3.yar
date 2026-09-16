rule Virus_Hijack_Gen_Trojan_ShellObject_DCZ_aSNPrTf_3 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.DCZ@aSNPrTf_3.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c34517ef1ed6b88b69f478e518736b401077deebc931116728a6c165bb5243bf"

  strings:
    $s1 = "access the documentation online at http://oracle.com/contracts. Se`" fullword ascii
    $s2 = "B%liSs" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}