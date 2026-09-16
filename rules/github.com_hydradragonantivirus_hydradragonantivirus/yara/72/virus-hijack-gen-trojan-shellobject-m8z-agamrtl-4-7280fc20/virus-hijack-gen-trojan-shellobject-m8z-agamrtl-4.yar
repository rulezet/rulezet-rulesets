rule Virus_Hijack_Gen_Trojan_ShellObject_m8Z_aGAMRTl_4 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.m8Z@aGAMRTl_4.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5ca7d3d3ffb0727b7efd1ab31c8a766679a62b96b416393a51b6aa17248071d1"

  strings:
    $s1 = "cprogram and/or materials resulting from services (or direct product thereof) will be exported, directly or indirectly, in viola" ascii
    $s2 = "cprogram and/or materials resulting from services (or direct product thereof) will be exported, directly or indirectly, in viola" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}