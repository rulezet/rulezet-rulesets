rule Trojan_Danger_Trojan_GenericKD_67166905_143_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.67166905_143_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "79a9cec986cd599481a11b13a51055083343acf5d1794b26eb5f855a66a51021"

  strings:
    $s1 = "'must be a Qualified Educational User to use software marked as " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}