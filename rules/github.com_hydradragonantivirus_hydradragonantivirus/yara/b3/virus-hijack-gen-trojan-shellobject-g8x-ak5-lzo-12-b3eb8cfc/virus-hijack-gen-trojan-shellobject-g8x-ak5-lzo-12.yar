rule Virus_Hijack_Gen_Trojan_ShellObject_g8X_aK5_lZo_12 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8X@aK5!lZo_12.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "58eb62bd0559316c033cf2fb835285659583b80e1943ccfcbaf9e2423be397cc"

  strings:
    $s1 = "Oncostman" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}