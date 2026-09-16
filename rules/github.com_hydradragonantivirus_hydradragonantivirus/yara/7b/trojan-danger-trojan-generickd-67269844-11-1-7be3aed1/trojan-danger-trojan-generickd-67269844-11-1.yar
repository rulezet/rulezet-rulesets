rule Trojan_Danger_Trojan_GenericKD_67269844_11_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.67269844_11_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "082d17a653c29b0cecb1a37a86c3a1f900dd8abbb027241add889945980ace3f"

  strings:
    $s1 = "s prior written consent.00" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}