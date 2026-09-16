rule Virus_Hijack_Gen_Trojan_ShellObject_eSW_amMcCQb_12 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.eSW@amMcCQb_12.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "554d23a13726975829e867c946955aec37b147cb9bb9076d992f7dfc4c9205bc"

  strings:
    $s1 = ")/whole number for purposes of license quantity requirements." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}