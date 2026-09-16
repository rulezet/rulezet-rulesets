rule Trojan_Autorun_Dump_Trojan_GenericKDZ_95048_30 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Trojan.GenericKDZ.95048_30.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2c05ab50dccaa53d2eb9419d2f19809e7877f942625b6aa33d8a954deff428ad"

  strings:
    $s1 = "613;gj>8>9;CorF@FACKwzNHNIKS" fullword ascii
    $s2 = "f`fack" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}