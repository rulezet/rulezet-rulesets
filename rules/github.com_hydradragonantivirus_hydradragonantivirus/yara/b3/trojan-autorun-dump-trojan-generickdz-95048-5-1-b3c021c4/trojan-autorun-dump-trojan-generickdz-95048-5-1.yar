rule Trojan_Autorun_Dump_Trojan_GenericKDZ_95048_5_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Trojan.GenericKDZ.95048_5_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d9444bcbe2dff949053e1197377692853ff1df807700fde9a43878ad95eb25b1"

  strings:
    $s1 = "informational links in this agreement. The links containing terms that bind you and`" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}