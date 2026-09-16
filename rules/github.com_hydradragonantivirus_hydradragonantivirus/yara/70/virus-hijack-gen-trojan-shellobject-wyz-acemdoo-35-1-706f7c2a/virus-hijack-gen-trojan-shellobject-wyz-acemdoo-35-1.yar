rule Virus_Hijack_Gen_Trojan_ShellObject_WyZ_aCEmdoo_35_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.WyZ@aCEmdoo_35_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d79d2901e6862e5a9718b3cbbef1b556c2df0feb4b7e93c312fedfc89f4fae85"

  strings:
    $s1 = "018-12-02T16:02:59+08:00\" stEvt:softwareAgent=\"Adobe Photoshop CC 2018 (Windows)\" stEvt:changed=\"/\"/> <rdf:li stEvt:action=" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}