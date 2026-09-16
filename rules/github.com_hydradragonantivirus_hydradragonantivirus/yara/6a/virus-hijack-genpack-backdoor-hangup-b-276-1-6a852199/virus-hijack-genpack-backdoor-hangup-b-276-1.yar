rule Virus_Hijack_GenPack_Backdoor_Hangup_B_276_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_GenPack.Backdoor.Hangup.B_276_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0f97ed6cc52cc0f356cf8067bd93162c8abbf04fb64b102b2ecb7446c5b0d9bf"

  strings:
    $s1 = "6-2.1\" xmpMM:InstanceID=\"xmp.iid:d5974899-ca88-7f42-9516-8e7635808df3\" xmpMM:DocumentID=\"adobe:docid:photoshop:953273c3-3fa6" ascii
    $s2 = "5-b6a0-ibaf393cacbc\" xmpMM:OriginalDocumentID=\"xmp.did:94317eb3-7085-4449-8680-030e5a0890d3\"> <xmpMM:History> <rdf:Seq>" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}