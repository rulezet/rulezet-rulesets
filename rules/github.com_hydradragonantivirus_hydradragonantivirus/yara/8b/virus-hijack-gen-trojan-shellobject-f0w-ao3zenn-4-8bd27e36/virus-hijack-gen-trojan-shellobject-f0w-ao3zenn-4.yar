rule Virus_Hijack_Gen_Trojan_ShellObject_f0W_aO3zEnn_4 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f0W@aO3zEnn_4.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "33274078e26e36691f464494063d261fa5abfcc8e3b04be3d9d2eeb8cc207bb1"

  strings:
    $s1 = "<dispute under this agreement to which Section B applies must be filed within one year in small claims" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}