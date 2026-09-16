rule Trojan_Danger_Trojan_GenericKD_72304918_10_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.72304918_10_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b24ad5dd71744413ebe9caf571ca452175ac8b001e273e10a44a7f494b8148ee"

  strings:
    $s1 = "gULa&Q>n" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}