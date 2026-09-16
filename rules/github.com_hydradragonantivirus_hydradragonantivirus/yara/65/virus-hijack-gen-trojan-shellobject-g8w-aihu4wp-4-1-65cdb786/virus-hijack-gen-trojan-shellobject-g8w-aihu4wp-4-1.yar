rule Virus_Hijack_Gen_Trojan_ShellObject_g8W_aiHu4Wp_4_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8W@aiHu4Wp_4_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e4ee4df409fe5837dddf89f1cc8f9abb548419425a065d20480afa4dce03d620"

  strings:
    $s1 = "Clien Local RunPross Auto" fullword wide
    $s2 = "OMFG Studio" fullword wide
    $s3 = "TODO: layout OLE  property page" fullword wide
    $s4 = "OMFG Studio All rights reserved." fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}