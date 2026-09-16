rule Trojan_Autorun_Trojan_GenericKD_72517131_137_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKD.72517131_137_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c191eb9a9bb0554da0e3bb3bbb74e987e5c80c6ad62455ca50b04eebefda6f15"

  strings:
    $s1 = "{by different names such as reseller, distributor" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}