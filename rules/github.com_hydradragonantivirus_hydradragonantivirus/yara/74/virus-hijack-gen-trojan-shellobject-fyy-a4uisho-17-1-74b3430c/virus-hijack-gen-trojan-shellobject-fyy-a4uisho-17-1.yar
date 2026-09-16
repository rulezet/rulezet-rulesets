rule Virus_Hijack_Gen_Trojan_ShellObject_fyY_a4uiSHo_17_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.fyY@a4uiSHo_17_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e890608a4cc37e0c648574caa821053c427732ba0afc2eaf432b635709d0d791"

  strings:
    $x1 = "cmd.exe /k ping 0 & del \"" fullword wide
    $s2 = "End process" fullword wide
    $s3 = "shutdown -l -t 00" fullword wide
    $s4 = "\" & exit" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    1 of ($x*) and all of them
}