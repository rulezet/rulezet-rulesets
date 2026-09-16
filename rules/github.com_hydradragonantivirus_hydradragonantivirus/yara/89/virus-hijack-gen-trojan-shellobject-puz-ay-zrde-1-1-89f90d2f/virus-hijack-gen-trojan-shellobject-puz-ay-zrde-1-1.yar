rule Virus_Hijack_Gen_Trojan_ShellObject_puZ_ay_ZRde_1_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.puZ@ay!ZRde_1_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f60c6a492f435c6cdd9962d2566f5872670251ace66d1d40c8f2a6311256815e"

  strings:
    $s1 = "gaw(LuMp" fullword ascii
    $s2 = "dELl]5" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}