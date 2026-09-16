rule Trojan_Autorun_Dump_Trojan_GenericKDZ_95048_5 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Trojan.GenericKDZ.95048_5.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "00082dcfb45ff6a3aa500d5881f0b5973a3f29f43a13062957664c02ce61a9a6"

  strings:
    $s1 = "613;gj>8>9;CorF@FACKwzNHNIKS" fullword ascii
    $s2 = "f`fack" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}