rule Virus_Sysbot_Trojan_GenericKD_71671752_20_1 {
  meta:
    description = "datamaliciousorder - file Virus.Sysbot_Trojan.GenericKD.71671752_20_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8d75e52db09f386ee5200c92edb19f4ca17bec81ab59e8ea543af69c1724fe1a"

  strings:
    $s1 = "IbeX$y-" fullword ascii
    $s2 = "`$RUNe%" fullword ascii
    $s3 = "SeLt  " fullword ascii
    $s4 = "C!Tale" fullword ascii
    $s5 = "s!i(KRAS" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}