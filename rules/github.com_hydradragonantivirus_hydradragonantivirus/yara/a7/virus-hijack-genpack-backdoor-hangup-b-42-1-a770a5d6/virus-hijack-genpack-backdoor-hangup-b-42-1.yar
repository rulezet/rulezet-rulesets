rule Virus_Hijack_GenPack_Backdoor_Hangup_B_42_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_GenPack.Backdoor.Hangup.B_42_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e275d758fc1b8567e220410d398ea7c193cace7ea7c8ea8a38cc5edc05217bea"

  strings:
    $s1 = "8:00\"`stEvt:softwareAgent=\"Adobe Photoshop CC 2018 (Windows)\"/> <rdf:li stEvt:action=\"saved\" stEvt:instanceID=\"xmp.iid:bda" ascii
    $s2 = "<rdf:li stEvt:action=\"created\" stEvt:instanceID=\"xmp.iid:94317eb3-7085-4449-8680-030e5a0890d3\" stEvt:when=\"2018-12-02T15:50" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}