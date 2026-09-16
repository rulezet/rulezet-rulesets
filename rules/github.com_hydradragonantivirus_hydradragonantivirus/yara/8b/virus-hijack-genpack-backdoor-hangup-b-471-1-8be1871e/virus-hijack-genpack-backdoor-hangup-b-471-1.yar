rule Virus_Hijack_GenPack_Backdoor_Hangup_B_471_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_GenPack.Backdoor.Hangup.B_471_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "48d4d04f8d791c2a4ebdf31dc061d05d56691aa878e1f3c10c2e2fc01e6a57c3"

  strings:
    $s1 = "Evt:softwareAgent=\"Adobe Pho" fullword ascii
    $s2 = "6-2.1\" xmpMM:InstanceID=\"xmp.iid:d5974899-ca88-7f42-9516-8e7635808df3\" xmpMM:DocumentID=\"adobe:docid:photoshop:953273c3-3fa6" ascii
    $s3 = "oshop CC 2018 (Windows)\"/> <rdf:li stEvt:action=\"saved\" stEvt:instanceID=\"xmp.iid:bda3dc4b-caee-fd46-b85f-119c665623ef\" stE" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}