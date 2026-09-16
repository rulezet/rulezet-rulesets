rule Trojan_Autorun_Dump_Trojan_GenericKDZ_95048_19 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Trojan.GenericKDZ.95048_19.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1d8b4f743187552a8ed8c52e18efb41f8585294056599cc7c537d28d349c18bd"

  strings:
    $s1 = "613;gj>8>9;CorF@FACKwzNHNIKS" fullword ascii
    $s2 = "8e9d=66;@mAlE>>CHuItMFFKP}Q|UNNSX" fullword ascii
    $s3 = "f`fack" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}