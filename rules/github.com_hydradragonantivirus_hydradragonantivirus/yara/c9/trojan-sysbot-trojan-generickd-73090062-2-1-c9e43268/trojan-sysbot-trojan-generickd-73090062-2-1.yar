rule Trojan_Sysbot_Trojan_GenericKD_73090062_2_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Sysbot_Trojan.GenericKD.73090062_2_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "42c3e9f7abee29096efad14a0d99e58d0f9f1bf2aee23ee0c0f92069d690a359"

  strings:
    $s1 = "Compile Script to .exe (x64).lnk" fullword ascii
    $s2 = "_ocq_cdp[aqqa[adsa[pore[gtr^rbf_cdra" fullword ascii
    $s3 = "iDyl:qd>6" fullword ascii
    $s4 = "dcsdrsbf[oacf[babr[oobt[bote`rpbe_ft" fullword ascii
    $s5 = "<F@`goFf" fullword ascii
    $s6 = "ANUs:[" fullword ascii
    $s7 = "|;SaNk" fullword ascii
    $s8 = "PACk>(" fullword ascii
    $s9 = "WeST'P" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}