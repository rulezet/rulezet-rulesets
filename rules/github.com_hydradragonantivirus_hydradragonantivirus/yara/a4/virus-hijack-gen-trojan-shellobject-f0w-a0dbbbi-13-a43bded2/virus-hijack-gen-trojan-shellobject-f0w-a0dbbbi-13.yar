rule Virus_Hijack_Gen_Trojan_ShellObject_f0W_a0DbbBi_13 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f0W@a0DbbBi_13.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8cfd1e56797039e8b40d0b8ffe2b3cdb677f482ed4c45742f2b4de78de3ca80e"

  strings:
    $s1 = "(dispute under this agreement to which Section B applies must be filed within one year in small claims" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}