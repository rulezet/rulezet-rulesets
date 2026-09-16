rule Virus_Hijack_Gen_Trojan_ShellObject_q8Z_aSQPfVg_2_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.q8Z@aSQPfVg_2_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5e08cb2f13887afb1ea321e4afd1679fe610d4a0bbce2edd73c07ce34421f379"

  strings:
    $s1 = "sALe)##z&F7c" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}