rule Virus_Hijack_Gen_Trojan_ShellObject_f0W_a0DbbBi_20 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f0W@a0DbbBi_20.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c103fa0d02d7b463bc32b8f3d326d80ed1d79a3a47fc9c13cff86ac58aab444e"

  strings:
    $s1 = "wdispute under this agreement to which Section B applies must be filed within one year in small claims" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}