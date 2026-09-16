rule Virus_Hijack_Gen_Trojan_ShellObject_fKX_aeBHSxm_2_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.fKX@aeBHSxm_2_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e0913fcd8041779ef69f28f9a392b725fb93fb0002e018c4e7d0950ca19176d1"

  strings:
    $s1 = "    --palette=PALETTE    specify the colors to use when --color is active" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}