rule Virus_Hijack_Gen_Trojan_ShellObject_DCZ_aSNPrTf_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.DCZ@aSNPrTf_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "21a0633d2781e85692073b4546dc955d4dcbe19a117332e5744cdadc5d107092"

  strings:
    $s1 = "access the documentation online at http://oracle.com/contracts. Se" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}