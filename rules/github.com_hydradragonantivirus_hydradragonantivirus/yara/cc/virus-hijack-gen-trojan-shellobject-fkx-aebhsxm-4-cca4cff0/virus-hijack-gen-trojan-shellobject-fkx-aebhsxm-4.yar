rule Virus_Hijack_Gen_Trojan_ShellObject_fKX_aeBHSxm_4 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.fKX@aeBHSxm_4.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ce2f4a2ee2dc2ece79915d8a7d17439266288763826da78fbd1c60d459bc80fb"

  strings:
    $s1 = "n.IRE_OLSA_V120103_Def_V122304 Page 1 of 11 " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}