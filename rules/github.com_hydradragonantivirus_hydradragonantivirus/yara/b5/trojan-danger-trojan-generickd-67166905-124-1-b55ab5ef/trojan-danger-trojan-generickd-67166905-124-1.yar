rule Trojan_Danger_Trojan_GenericKD_67166905_124_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.67166905_124_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c44356d1e9baf7f330e1f4d716a023ee559ca60c493032a3d923cac59c55b158"

  strings:
    $s1 = "nRSoftware Assurance." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}