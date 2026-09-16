rule Virus_Hijack_Gen_Trojan_ShellObject_puZ_ay_ZRde_4_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.puZ@ay!ZRde_4_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "16da4ae8112d1235257fd74a5c6f14cd6e6ecefeaaac5fbe90cde55fb1f9f520"

  strings:
    $s1 = "{bizz}G1" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}