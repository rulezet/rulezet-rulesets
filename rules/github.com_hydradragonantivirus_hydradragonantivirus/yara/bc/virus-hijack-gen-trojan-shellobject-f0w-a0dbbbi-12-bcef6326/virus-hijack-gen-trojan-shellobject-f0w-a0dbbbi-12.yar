rule Virus_Hijack_Gen_Trojan_ShellObject_f0W_a0DbbBi_12 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f0W@a0DbbBi_12.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d2b92dbb46e190184aee79f4fc67157135586663736a75eb1ab103cd49613813"

  strings:
    $s1 = "%Ydispute under this agreement to which Section B applies must be filed within one year in small claims" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}