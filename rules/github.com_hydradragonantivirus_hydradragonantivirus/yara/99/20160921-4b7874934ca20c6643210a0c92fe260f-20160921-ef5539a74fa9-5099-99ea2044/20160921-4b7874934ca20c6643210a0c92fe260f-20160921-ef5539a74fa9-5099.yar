rule _20160921_4b7874934ca20c6643210a0c92fe260f_20160921_ef5539a74fa9_5099 {
  meta:
    description = "datamaliciousorder - from files 20160921_4b7874934ca20c6643210a0c92fe260f.js, 20160921_ef5539a74fa92cc432f92987e238b0be.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "858cb8ac4dab1ec1e6a2a0bb435765157525269e75820991212eee18a2d91717"
    hash2       = "6a7080b4743207e49b99932d406b2ee18d652ac2222bdb5a88a66af8dea13c80"

  strings:
    $s1 = "fuck(){return \"AUx\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"M" ascii
    $s2 = "turn \"YQt\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"MBg\";})()" ascii
    $s3 = "uck(){return \"LGo\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"NK" ascii
    $s4 = "ck(){return \"Et\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"Jg\";})(),(function fuck(){return \"IPu\";" ascii
    $s5 = "Go\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"MBg\";})(),(functi" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}