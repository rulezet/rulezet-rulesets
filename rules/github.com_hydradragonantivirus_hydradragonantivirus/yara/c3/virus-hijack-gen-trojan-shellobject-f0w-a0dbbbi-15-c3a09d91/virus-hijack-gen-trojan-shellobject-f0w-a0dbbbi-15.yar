rule Virus_Hijack_Gen_Trojan_ShellObject_f0W_a0DbbBi_15 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f0W@a0DbbBi_15.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7657c0598725ca53b0052cc76f9571e727cb7d1cd35e852692db9708809d2df9"

  strings:
    $s1 = "{dispute under this agreement to which Section B applies must be filed within one year in small claims" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}