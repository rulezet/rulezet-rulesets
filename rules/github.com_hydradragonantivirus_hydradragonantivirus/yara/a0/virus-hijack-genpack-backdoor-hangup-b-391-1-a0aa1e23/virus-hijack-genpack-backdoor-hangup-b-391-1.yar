rule Virus_Hijack_GenPack_Backdoor_Hangup_B_391_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_GenPack.Backdoor.Hangup.B_391_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0a495bf02224a35310101778423bb6498f132c1129cc932af1a14a9fb98f0877"

  strings:
    $s1 = "Evt:softwareAgent=\"Adobe Photoshop CC 2018 (Windows)\"/> <rdf:li stEvt:action=\"saved\" stEvt:instanceID" fullword ascii
    $s2 = "6-2.1\" xmpMM:InstanceID=\"xmp.iid:d5974899-ca88-7f42-9516-8e7635808df3\" xmpMM:DocumentID=\"adobe:docid:photoshop:953273c3-3fa6" ascii
    $s3 = "\"xmp.iid:bda3dc4b-caee-fd46-b85f-119c665623ef\" stEvt:when=\"2018-12-02T16:02:59+08:00\" stEvt:softwareAgent=\"Adobe Photoshop " ascii
    $s4 = "\"xmp.iid:bda3dc4b-caee-fd46-b85f-119c665623ef\" stEvt:when=\"2018-12-02T16:02:59+08:00\" stEvt:softwareAgent=\"Adobe Photoshop " ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}