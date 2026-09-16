rule Trojan_Danger_Trojan_GenericKD_72304918_4_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.72304918_4_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7fcae4f4654ebc5eb57707d22cc8a37c974a7906e09f8b19296ba4298e89b08c"

  strings:
    $s1 = "tanh$e" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}