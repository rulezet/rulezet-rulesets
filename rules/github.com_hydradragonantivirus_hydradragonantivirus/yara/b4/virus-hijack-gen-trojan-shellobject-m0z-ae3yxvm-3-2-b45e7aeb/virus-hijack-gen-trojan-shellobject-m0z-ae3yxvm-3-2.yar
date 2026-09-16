rule Virus_Hijack_Gen_Trojan_ShellObject_m0Z_ae3yXvm_3_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.m0Z@ae3yXvm_3_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "630a2944626ced06d78407b07449b60611a49b34270c2c5647dff6cc378d9d84"

  strings:
    $s1 = "JC%AZOn" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}