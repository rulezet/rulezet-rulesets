rule Virus_Danger_Gen_Trojan_ShellObject_fKX_aeBHSxm {
  meta:
    description = "datamaliciousorder - file Virus.Danger_Gen.Trojan.ShellObject.fKX@aeBHSxm.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "32e94886b9894e6cb109f49ff9579b9d3059de70d6a8882affc75f9698d27684"

  strings:
    $s1 = " hIRE_OLSA_V120103_Def_V122304 Page 1 of 11 " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}