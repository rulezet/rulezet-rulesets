rule Trojan_Hooker_Trojan_GenericKD_30823331 {
  meta:
    description = "datamaliciousorder - file Trojan.Hooker_Trojan.GenericKD.30823331.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7272383f07deefcc42e667405891916a885b3c5a11067f2e2dc6b90b58fcee69"

  strings:
    $s1  = "  <description>anticipe'e</description> " fullword ascii
    $s2  = "WinSCP: SFTP, FTP and SCP client" fullword wide
    $s3  = "antecedental" fullword ascii
    $s4  = "Faultlessly" fullword ascii
    $s5  = "Overrigid" fullword ascii
    $s6  = "Abortionist" fullword ascii
    $s7  = "Finitely" fullword ascii
    $s8  = "(c) 2000-2012 Martin Prikryl" fullword wide
    $s9  = "Fibril" fullword ascii
    $s10 = "Attend" fullword ascii
    $s11 = "Chimerical" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    8 of them
}