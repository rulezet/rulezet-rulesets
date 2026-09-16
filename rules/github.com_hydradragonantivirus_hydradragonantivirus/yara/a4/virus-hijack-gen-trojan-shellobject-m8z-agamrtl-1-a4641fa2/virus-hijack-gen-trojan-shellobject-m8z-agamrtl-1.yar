rule Virus_Hijack_Gen_Trojan_ShellObject_m8Z_aGAMRTl_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.m8Z@aGAMRTl_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4ce59925e5e3bec479137daea9688ed95c924d81ad3e81293addb957be7360c0"

  strings:
    $s1 = "5program and/or materials resulting from services (or direct product thereof) will be exported, directly or indirectly, in viola" ascii
    $s2 = "5program and/or materials resulting from services (or direct product thereof) will be exported, directly or indirectly, in viola" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}