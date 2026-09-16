rule Virus_Hijack_Gen_Trojan_ShellObject_xSZ_amMcCQb_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.xSZ@amMcCQb_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6acafa1b8995d724aca6ee4a2365c83e1d65e7ad2d9b3e54e28396c1751c57ff"

  strings:
    $s1 = "4whole number for purposes of license quantity requirements." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}