rule Trojan_Autorun_Dump_Generic_Mira_575DCBBE_1_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Mira.575DCBBE_1_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a1b72b5669f7daa328da0e6b6b22038092f96f75309949a50d2cfe6a52cc0ea7"

  strings:
    $s1 = "OveN*J" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}