rule Virus_Hijack_Gen_Trojan_ShellObject_f0W_a0DbbBi_22 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f0W@a0DbbBi_22.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "80ae489acec67049319b073c62c38fa77e906de55b554b784a9d05169f4a8ae8"

  strings:
    $s1 = "Sdispute under this agreement to which Section B applies must be filed within one year in small claims" fullword ascii
    $s2 = "nX`FEEd" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}