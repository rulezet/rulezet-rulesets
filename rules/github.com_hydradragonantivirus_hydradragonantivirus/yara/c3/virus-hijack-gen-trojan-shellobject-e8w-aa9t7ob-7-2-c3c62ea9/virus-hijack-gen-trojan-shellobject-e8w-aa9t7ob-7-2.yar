rule Virus_Hijack_Gen_Trojan_ShellObject_e8W_aa9T7Ob_7_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.e8W@aa9T7Ob_7_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b7b65c8e68fddeee42f602ff3905a1362451c49638b67b9cfa94033e1b8e7d03"

  strings:
    $s1 = "\"%s\" start \"%s\"" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}