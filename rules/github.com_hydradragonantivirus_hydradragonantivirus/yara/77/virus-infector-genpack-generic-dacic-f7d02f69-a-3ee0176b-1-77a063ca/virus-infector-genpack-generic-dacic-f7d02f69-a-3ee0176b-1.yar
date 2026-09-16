rule Virus_Infector_GenPack_Generic_Dacic_F7D02F69_A_3EE0176B_1 {
  meta:
    description = "datamaliciousorder - file Virus.Infector_GenPack.Generic.Dacic.F7D02F69.A.3EE0176B_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d1d9ae11b43eed98fa734c20b198db31e737fd6edfa72b29767f791f2d0493ab"

  strings:
    $s1 = "a88-7f42-9516-8e7635808df3\" xmpMM:DocumentID=\"adobe:docid:photoshop:953273c3-3fa6-8f45-b6a0-9baf393cacbc\" xmpMM:OriginalDocum" ascii
    $s2 = "ID=\"xmp.did:94317eb3-7085-4449-8680-030e5a0890d3\"> <xmpMM:History> <rdf:Seq> <rdf:li stEvt:action=\"created\" stEvt:instanceID" ascii
    $s3 = "a88-7f42-9516-8e7635808df3\" xmpMM:DocumentID=\"adobe:docid:photoshop:953273c3-3fa6-8f45-b6a0-9baf393cacbc\" xmpMM:OriginalDocum" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}