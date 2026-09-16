rule Virus_Hijack_Gen_Trojan_ShellObject_dWW_aOfWMFe_4_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.dWW@aOfWMFe_4_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "44b165a8472f46fae207a0eae6c3d193ab5f6468f746317fca9c0d22405d9105"

  strings:
    $s1 = " width$1" fullword ascii
    $s2 = "Pobs'$" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}