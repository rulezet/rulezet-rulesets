rule Virus_Hijack_Gen_Trojan_ShellObject_e8W_a8TFxTj {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.e8W@a8TFxTj.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d370ac7cc24bc71bc5f8685a2e9bb13bf5c2dd95ca6ad8e69bd917529c176214"

  strings:
    $s1 = "(month pe" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}