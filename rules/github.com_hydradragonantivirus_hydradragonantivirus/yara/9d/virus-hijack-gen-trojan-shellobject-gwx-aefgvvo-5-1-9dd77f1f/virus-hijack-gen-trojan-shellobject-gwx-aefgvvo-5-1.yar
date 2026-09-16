rule Virus_Hijack_Gen_Trojan_ShellObject_gWX_aeFgVVo_5_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.gWX@aeFgVVo_5_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "753195454a60741d52951f66338eaaf5b8240a29dfe4e4815e0e554e9d0248ff"

  strings:
    $s1 = "Definably" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}