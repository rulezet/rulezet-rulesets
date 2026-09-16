rule _Virus_Hijack_Trojan_Agent_DQQO_129_2_Virus_Hijack_Trojan_Agent__261 {
  meta:
    description = "datamaliciousorder - from files Virus.Hijack_Trojan.Agent.DQQO_129_2.vir, Virus.Hijack_Trojan.Agent.DQQO_131_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a50aff091dd28a51809341e296439a53d7d45c5616502122ad8b429408b3ec76"
    hash2       = "3c4fb3b16b83c56c39643c3dd0d8c5afca180bf163c5847bef5f4a8fd8b5896a"

  strings:
    $s1 = "Description of error no. %d missing" fullword ascii
    $s2 = "C:\\Programme\\Microsoft Visual Studio 9.0\\VC\\atlmfc\\include\\afxwin1.inl" fullword ascii
    $s3 = "File %s is not complete." fullword ascii
    $s4 = "Il file %s dev'essere compleato. Manca la descrizione del errore %d." fullword ascii
    $s5 = " possibile scrivere il file %s." fullword ascii
    $s6 = "Cannot access file %s in write mode." fullword ascii
    $s7 = "Nach %s = new ..." fullword ascii

  condition:
    (uint16(0) == 0x5a4d and (all of them)
    ) or (all of them)
}