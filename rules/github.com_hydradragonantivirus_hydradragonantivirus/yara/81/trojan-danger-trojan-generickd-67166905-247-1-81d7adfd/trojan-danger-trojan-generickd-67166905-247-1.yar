rule Trojan_Danger_Trojan_GenericKD_67166905_247_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.67166905_247_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "617efd65e6474d9b0961aadce3ede6b760a1254210db239ff676e3d3dcfcf2e1"

  strings:
    $s1 = "/policy, which might require you to return the software with the entire computer on which the software is" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}