rule Virus_Injector_Trojan_Patched_BU_1_1 {
  meta:
    description = "datamaliciousorder - file Virus.Injector_Trojan.Patched.BU_1_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "700bedd145515122e216dc34e9d26974e4efdcec3885f14b64514d2332bd4e47"

  strings:
    $s1 = " (joLL" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}