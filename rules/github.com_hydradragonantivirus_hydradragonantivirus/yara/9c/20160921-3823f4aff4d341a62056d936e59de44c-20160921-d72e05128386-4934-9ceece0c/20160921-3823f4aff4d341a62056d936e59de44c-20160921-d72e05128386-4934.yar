rule _20160921_3823f4aff4d341a62056d936e59de44c_20160921_d72e05128386_4934 {
  meta:
    description = "datamaliciousorder - from files 20160921_3823f4aff4d341a62056d936e59de44c.js, 20160921_d72e05128386ec5185fa7c82a29fe618.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d0b475c02138425371c1df69faa8ac5c3d739764950c4a65034372b4455ac04d"
    hash2       = "72502e65294651208a74590dc961703c09931d4341f59214d7303b271ca8abd5"

  strings:
    $s1 = ")(),(function fuck(){return \"Ot\";})(),(function fuck(){return \"MIl\";})(),(function fuck(){return \"Za\";})(),(function fuck(" ascii
    $s2 = "fuck(){return \"MBg\";})(),(function fuck(){return \"IKv\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"Ai" ascii
    $s3 = "nction fuck(){return \"Mw\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){retur" ascii
    $s4 = ",(function fuck(){return \"Vb\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){re" ascii
    $s5 = "return \"IPu\";})(),(function fuck(){return \"Vf\";})(),(function fuck(){return \"To\";})(),(function fuck(){return \"EHo\";})()" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}