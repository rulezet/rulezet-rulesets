rule Virus_Hijack_Gen_Trojan_ShellObject_eSX_amMcCQb_6 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.eSX@amMcCQb_6.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2daf6e66b2666ef0f410d2b78ae8749850ae77bcec4378c975ab178089e45ec7"

  strings:
    $s1 = "8Uwhole number for purposes of license quantity requirements." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}