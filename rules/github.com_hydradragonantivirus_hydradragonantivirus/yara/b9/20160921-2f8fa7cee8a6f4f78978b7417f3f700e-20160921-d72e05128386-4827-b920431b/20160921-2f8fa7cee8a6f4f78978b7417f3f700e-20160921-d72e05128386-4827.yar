rule _20160921_2f8fa7cee8a6f4f78978b7417f3f700e_20160921_d72e05128386_4827 {
  meta:
    description = "datamaliciousorder - from files 20160921_2f8fa7cee8a6f4f78978b7417f3f700e.js, 20160921_d72e05128386ec5185fa7c82a29fe618.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6410122a95cd840a4eef622389d8026475b4f6a156d4b5288cf227165c036c96"
    hash2       = "72502e65294651208a74590dc961703c09931d4341f59214d7303b271ca8abd5"

  strings:
    $s1 = "return \"Sx\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";})()" ascii
    $s2 = "nction fuck(){return \"MBg\";})(),(function fuck(){return \"Wo\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){retur" ascii
    $s3 = "rn \"Cd\";})(),(function fuck(){return \"MIl\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"UOe\";})(),(fu" ascii
    $s4 = "urn \"RAi\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"GNm\";})(),(" ascii
    $s5 = "on fuck(){return \"IPu\";})(),(function fuck(){return \"Et\";})(),(function fuck(){return \"Et\";})(),(function fuck(){return \"" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}