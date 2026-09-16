rule Virus_Hijack_Gen_Trojan_ShellObject_eSW_amMcCQb_11 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.eSW@amMcCQb_11.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4a0a6857dc2b25f944a42cd459bcedb02f86f07dc24288f04f6d8037217f96cb"

  strings:
    $s1 = "Vwhole number for purposes of license quantity requirements." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}