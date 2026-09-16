rule Trojan_Sysbot_Trojan_GenericKDZ_104643_75_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Sysbot_Trojan.GenericKDZ.104643_75_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5020ac41bb296c5453df622c29b6c8eb693a6f84f85acfbbb037748854039a2d"

  strings:
    $s1 = "TRap?<RRRRRRRRRRRRRRRRRRna" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}