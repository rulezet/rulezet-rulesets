rule Virus_Hijack_Gen_Trojan_ShellObject_fWW_a41FOHj_3_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.fWW@a41FOHj_3_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ef295d4914256847b5f0accbc001a5dda588e05e0c85fcb479eca30cb17aee18"

  strings:
    $x1 = "cmd.exe /c ping 127.0.0.1 & del \"" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    1 of ($x*)
}