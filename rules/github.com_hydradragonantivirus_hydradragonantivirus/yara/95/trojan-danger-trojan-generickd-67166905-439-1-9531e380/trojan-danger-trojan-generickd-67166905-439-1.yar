rule Trojan_Danger_Trojan_GenericKD_67166905_439_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.67166905_439_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3feb0e70adbf7f4ba34d5cb12f294112af44b563ff29679094d3eab73bcbd56b"

  strings:
    $s1 = "bpurposes of counting the number of processors which require licensing, a multicore chip with \"n\" processor cores shall be" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}