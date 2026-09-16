rule Trojan_Autorun_Dropped_Generic_Dacic_06B5CF0E_A_3A6AA980_15_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dropped.Generic.Dacic.06B5CF0E.A.3A6AA980_15_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6f904fd25f2da03275b7cf30b8ebba8358a9b0707859932fc709725a16dbfb74"

  strings:
    $s1 = "This program must be run under Win32C" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}