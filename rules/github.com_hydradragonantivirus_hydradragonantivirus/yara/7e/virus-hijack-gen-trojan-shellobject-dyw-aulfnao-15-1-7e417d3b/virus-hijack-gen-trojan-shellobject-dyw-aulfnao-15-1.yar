rule Virus_Hijack_Gen_Trojan_ShellObject_dyW_auLFnao_15_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.dyW@auLFnao_15_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5a37df41c699de4db40cce4ccb3bd9388a1cfb9691b803572effd6bf01a42514"

  strings:
    $x1 = "cmd.exe /c ping 127.0.0.1 & del \"" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    1 of ($x*)
}