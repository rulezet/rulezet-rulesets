rule Trojan_Autorun_Dump_Generic_Dacic_19E38D3B_A_AAF775A0_242_2 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.19E38D3B.A.AAF775A0_242_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "74adfb1e411d413de7b9b5162d9ef622e427ee734494cedc6df34d2e19dc8fce"

  strings:
    $s1 = "binO<O" fullword ascii
    $s2 = "'[,goel" fullword ascii
    $s3 = "#doUc}" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}