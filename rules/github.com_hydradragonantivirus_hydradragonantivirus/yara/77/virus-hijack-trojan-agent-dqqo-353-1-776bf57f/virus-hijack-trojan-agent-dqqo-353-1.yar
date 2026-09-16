rule Virus_Hijack_Trojan_Agent_DQQO_353_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.Agent.DQQO_353_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2fb808dfd42f2b92da620051c09220b89d38ef2eec0b413ce33dc486406da927"

  strings:
    $s1 = "6-2.1\" xmpMM:InstanceID=\"xmp.iid:d5974899-ca88-7f42-9516-8e7635808df3\" xmpMM:DocumentID=\"adobe:docid:photoshop:953273c3-3fa6" ascii
    $s2 = "5-b6a0-ibaf393cacbc\" xmpMM:OriginalDocumentID=\"xmp.did:94317eb3-7085-4449-8680-030e5a0890d3\"> <xmpMM:History> <rdf:Seq>" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}