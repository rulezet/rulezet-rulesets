rule Virus_Hijack_Gen_Trojan_ShellObject_m8Z_aGAMRTl {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.m8Z@aGAMRTl.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "37d730783d62e0095f2cce0cfbfea8c825d016b4623745ab9470f1a9a92624c7"

  strings:
    $s1 = "`program and/or materials resulting from services (or direct product thereof) will be exported, directly or indirectly, in viola" ascii
    $s2 = "`program and/or materials resulting from services (or direct product thereof) will be exported, directly or indirectly, in viola" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}