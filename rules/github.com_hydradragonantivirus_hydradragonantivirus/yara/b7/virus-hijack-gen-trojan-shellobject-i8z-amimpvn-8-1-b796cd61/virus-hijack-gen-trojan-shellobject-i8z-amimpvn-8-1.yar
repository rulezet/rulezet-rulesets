rule Virus_Hijack_Gen_Trojan_ShellObject_i8Z_amIMPvn_8_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.i8Z@amIMPvn_8_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a65391e1baec55fec364cfd6968c4f0df85270be7896ddd149bb8961d47d8bc9"

  strings:
    $s1 = "!Error Download" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}