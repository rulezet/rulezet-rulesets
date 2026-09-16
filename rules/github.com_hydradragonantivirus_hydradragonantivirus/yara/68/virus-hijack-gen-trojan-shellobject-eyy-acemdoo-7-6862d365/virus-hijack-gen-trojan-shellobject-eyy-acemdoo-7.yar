rule Virus_Hijack_Gen_Trojan_ShellObject_eyY_aCEmdoo_7 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.eyY@aCEmdoo_7.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "099a3d63bca0c468f40f7fe452af975ff4a71a195932ce6b2c6a301a6a97425b"

  strings:
    $s1 = "M,coPE" fullword ascii
    $s2 = "M,coPe" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}