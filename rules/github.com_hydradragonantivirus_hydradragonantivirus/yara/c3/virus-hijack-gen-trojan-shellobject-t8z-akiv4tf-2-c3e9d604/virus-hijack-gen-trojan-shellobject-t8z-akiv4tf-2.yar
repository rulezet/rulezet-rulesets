rule Virus_Hijack_Gen_Trojan_ShellObject_t8Z_aKiV4Tf_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.t8Z@aKiV4Tf_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "46a1b8b13e40e7b502bac26f1a5a9a4a236bb0fe14a336cb9db2bc1d7b58badf"

  strings:
    $s1 = ".virtualization, see the Additional Terms." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}