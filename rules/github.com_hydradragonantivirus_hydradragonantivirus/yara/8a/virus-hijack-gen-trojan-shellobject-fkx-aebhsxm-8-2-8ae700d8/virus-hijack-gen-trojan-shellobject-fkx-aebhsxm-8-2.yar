rule Virus_Hijack_Gen_Trojan_ShellObject_fKX_aeBHSxm_8_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.fKX@aeBHSxm_8_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b8420dd08b486a0050893ba8e502261d4f732d976e62fa2553e919da624eca1f"

  strings:
    $s1 = "AReserved Context" fullword wide
    $s2 = "e<MESSAGE>" fullword wide
    $s3 = "gBase property for prstNil" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}