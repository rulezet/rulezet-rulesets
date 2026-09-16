rule Trojan_Autorun_Dump_Generic_Dacic_19E38D3B_A_AAF775A0_99_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.19E38D3B.A.AAF775A0_99_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2988d23659cf03acc8a09bcb53ea757258f5233962c73ac1c3f8158d78b1e4fb"

  strings:
    $s1 = "Z&and services at the list price in effect at the " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}