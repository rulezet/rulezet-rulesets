rule Virus_Hijack_Gen_Trojan_ShellObject_uvZ_a8bSq4i_3_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.uvZ@a8bSq4i_3_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1adb3bfdcc8bbde43a8bb07c13dabb034650de657575be817dc4f092beef5988"

  strings:
    $s1 = "Flicks Training" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}