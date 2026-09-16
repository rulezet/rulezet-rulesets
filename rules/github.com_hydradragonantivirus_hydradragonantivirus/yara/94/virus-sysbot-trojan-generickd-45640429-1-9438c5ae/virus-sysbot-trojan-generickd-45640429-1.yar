rule Virus_Sysbot_Trojan_GenericKD_45640429_1 {
  meta:
    description = "datamaliciousorder - file Virus.Sysbot_Trojan.GenericKD.45640429_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "634a03f8fa2d3c53abe2cb933ccf798be4944cde0eb997fafb2d971c8f4f9e32"

  strings:
    $s1 = "@~~@Window Updates@~~@1@~~@" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}