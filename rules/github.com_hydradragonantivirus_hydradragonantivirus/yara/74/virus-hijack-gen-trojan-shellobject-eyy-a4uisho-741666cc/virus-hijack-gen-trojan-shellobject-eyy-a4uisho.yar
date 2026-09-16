rule Virus_Hijack_Gen_Trojan_ShellObject_eyY_a4uiSHo {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.eyY@a4uiSHo.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "53c4d903c53012eb9751f92d61a22cc43ab35946e113eeed93856dbf89aaf3bd"

  strings:
    $s1 = "2b:Cite" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}