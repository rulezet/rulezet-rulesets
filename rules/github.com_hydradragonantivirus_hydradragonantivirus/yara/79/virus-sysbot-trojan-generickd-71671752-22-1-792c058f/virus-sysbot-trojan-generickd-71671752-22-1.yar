rule Virus_Sysbot_Trojan_GenericKD_71671752_22_1 {
  meta:
    description = "datamaliciousorder - file Virus.Sysbot_Trojan.GenericKD.71671752_22_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b3968afdbb5ca49de5817f3f35628606e50ad2706c285e68240f994887231bca"

  strings:
    $s1 = "<description>PE/COFF File Viewer.</description>" fullword ascii
    $s2 = "PE/COFF File Viewer" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}