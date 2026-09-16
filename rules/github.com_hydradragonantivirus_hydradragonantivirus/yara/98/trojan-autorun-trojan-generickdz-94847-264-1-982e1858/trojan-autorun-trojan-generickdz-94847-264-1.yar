rule Trojan_Autorun_Trojan_GenericKDZ_94847_264_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKDZ.94847_264_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ec1476a80b6bf3757ebdfae5a261b415c90b640bd9dd35033742317c928d8b25"

  strings:
    $s1 = "VAorders during any 12 month period." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}