rule VirusShareTrojanSiggen1961528_10_1 {
  meta:
    description = "datamaliciousorder - file VirusShareTrojanSiggen1961528_10_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4e6e6547c384f489b1666e3f9e026c992fcf416f6ce090b4a6b678e361d03dbf"

  strings:
    $s1 = "Boo.Lang.Builtins+<range>c__Iterator2" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}