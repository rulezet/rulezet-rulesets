rule Trojan_Danger_Trojan_GenericKD_72677122_193_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.72677122_193_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0dccb406cfd0a30f970c73d5e2bcf40cbf0a4e254a5798a216be05f5495e5725"

  strings:
    $s1 = "sc config WinDefend start= disabled" fullword ascii
    $s2 = "sc config MpsSvc start= disabled" fullword ascii
    $s3 = "net stop WinDefend" fullword ascii
    $s4 = "net stop MpsSvc" fullword ascii
    $s5 = "[yd}bony6.[yd}bony." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}