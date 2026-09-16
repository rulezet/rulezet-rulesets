rule Virus_Hijack_Gen_Trojan_ShellObject_eSX_amMcCQb_4 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.eSX@amMcCQb_4.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "eba398064c7f6d8e7d9c75f3d2e147a21cd91d62582ceaf0ba6105dd7fe1facc"

  strings:
    $s1 = " whole number for purposes of license quantity requirements." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}