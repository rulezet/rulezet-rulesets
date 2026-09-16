rule Virus_Hijack_Gen_Trojan_ShellObject_C8Z_amCvSwc_9 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.C8Z@amCvSwc_9.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a44a925ef0cd572e37687a18a2a1cfffdbd027ade49da6ae79e7057cb283be3d"

  strings:
    $s1 = "(NASi'" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}