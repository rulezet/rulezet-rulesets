rule Virus_Hijack_Gen_Trojan_ShellObject_i8Z_amIMPvn_5 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.i8Z@amIMPvn_5.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "79e626a8bdefd7a120776d931c28caac3eba12a60821602138b788abbfb4f0ce"

  strings:
    $s1 = "=policy, which might require you to return the software with the entire computer on which the software is" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}