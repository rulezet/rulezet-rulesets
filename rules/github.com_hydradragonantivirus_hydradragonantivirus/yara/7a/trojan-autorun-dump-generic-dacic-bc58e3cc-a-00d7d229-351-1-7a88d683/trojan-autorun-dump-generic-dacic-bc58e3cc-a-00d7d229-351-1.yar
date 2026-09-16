rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_351_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_351_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9fafd7798e94332bbc72ae453824d9c900be155f502bfb04247b5903e1c2533b"

  strings:
    $s1 = "You may temporarily download the fonts to a prin" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}