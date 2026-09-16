rule Trojan_Autorun_Gen_Heur_Mint_SP_Urelas_1_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Gen.Heur.Mint.SP.Urelas.1_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4794f9a9ade9e158b54b8396d270aaccde9c7ef2e841667f2c160e90e5714c5a"

  strings:
    $s1  = "library incorrect" fullword ascii
    $s2  = "result of c" fullword ascii
    $s3  = "from this assem" fullword ascii
    $s4  = " Class Hierarchy Descript" fullword ascii
    $s5  = " delete[] clos" fullword ascii
    $s6  = "Read |" fullword ascii
    $s7  = "bly during n]v" fullword ascii
    $s8  = "Help!PN" fullword ascii
    $s9  = "{Copy*ztIn" fullword ascii
    $s10 = "8 Mark Adler{" fullword ascii
    $s11 = "@y been parily " fullword ascii
    $s12 = "Please contac91]" fullword ascii
    $s13 = ". It Zmost like]" fullword ascii
    $s14 = "Flush&BuffersL6Po" fullword ascii
    $s15 = "MODULE%S" fullword ascii
    $s16 = "as made a" fullword ascii
    $s17 = " team f" fullword ascii
    $s18 = " tree#" fullword ascii
    $s19 = "s#size" fullword ascii
    $s20 = "`place" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    8 of them
}