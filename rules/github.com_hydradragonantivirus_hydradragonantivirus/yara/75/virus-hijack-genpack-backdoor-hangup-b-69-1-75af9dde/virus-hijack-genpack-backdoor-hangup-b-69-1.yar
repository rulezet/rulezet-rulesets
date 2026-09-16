rule Virus_Hijack_GenPack_Backdoor_Hangup_B_69_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_GenPack.Backdoor.Hangup.B_69_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d7fdf915925b92aeca50434fd70692002032a04f48671d6c0766e06a570f32bb"

  strings:
    $s1 = "<rdf:li stEvt:action=\"created\" stEvt:instanceID=\"xmp.iid:94317eb3-7085-4449-8680-030e5a0890d3\" stEvt:when=\"2018-12-02T15:50" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}