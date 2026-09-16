rule Trojan_Danger_Trojan_GenericKD_72853156_386_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.72853156_386_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "41fc757ff4d6e5ec40aab00b2a88480163bbc852a3fbd18a30ffd2eda3e2214c"

  strings:
    $s1 = "availability of ExtenSysqemofnueSysqemelkmtSysqamqqvaqqdSysqamqqvaqqdSysqamqqvaqqdSysqamqqvaqqdSysqamqqvaqqdSysqamqqvaqqdSysqamq" ascii
    $s2 = "availability of ExtenSysqemofnueSysqemelkmtSysqamqqvaqqdSysqamqqvaqqdSysqamqqvaqqdSysqamqqvaqqdSysqamqqvaqqdSysqamqqvaqqdSysqamq" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}