rule Virus_Hijack_Gen_Trojan_ShellObject_i8Z_amIMPvn_10 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.i8Z@amIMPvn_10.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "534088090d233e7b51539dd898aae85c054dd0b89fabdccdacd6843b0c53ca9a"

  strings:
    $s1 = "dpolicy, which might require you to return the software with the entire computer on which the software is" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}