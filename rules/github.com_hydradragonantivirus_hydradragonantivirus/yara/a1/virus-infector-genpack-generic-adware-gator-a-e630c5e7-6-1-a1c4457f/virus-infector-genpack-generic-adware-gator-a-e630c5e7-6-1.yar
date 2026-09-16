rule Virus_Infector_GenPack_Generic_Adware_Gator_A_E630C5E7_6_1 {
  meta:
    description = "datamaliciousorder - file Virus.Infector_GenPack.Generic.Adware.Gator.A.E630C5E7_6_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9917566caaef4753206a5282b35fd7d69a4f07161ccf8d2cfce60998b3fecc46"

  strings:
    $s1 = "wareAgent=\"Adobe Photoshop CC 2018 (Windows)\" stEvt:changed=\"/\"/> <rdf:li stEvt:action=\"converted\" stEvt:parameters=\"from" ascii
    $s2 = ",Reference Viewing Condition in IE" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}