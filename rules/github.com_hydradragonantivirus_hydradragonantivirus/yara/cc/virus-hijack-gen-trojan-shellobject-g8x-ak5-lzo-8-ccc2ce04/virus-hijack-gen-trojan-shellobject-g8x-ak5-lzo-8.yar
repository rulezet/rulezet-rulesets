rule Virus_Hijack_Gen_Trojan_ShellObject_g8X_aK5_lZo_8 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8X@aK5!lZo_8.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "212f0e65dc9098503edd415674b2581a2c2bb2bb250db6f12e956902063c249c"

  strings:
    $s1 = "DqUniversity Online Library (" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}