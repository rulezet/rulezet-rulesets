rule _20160921_06a7c56eaf19048ede06f33b655f2bc5_20160921_4b7874934ca2_3262 {
  meta:
    description = "datamaliciousorder - from files 20160921_06a7c56eaf19048ede06f33b655f2bc5.js, 20160921_4b7874934ca20c6643210a0c92fe260f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3971833c2ab49de293c47181e999db88e5cad0eaddc5aa38a2516eeac1cab29d"
    hash2       = "858cb8ac4dab1ec1e6a2a0bb435765157525269e75820991212eee18a2d91717"

  strings:
    $s1 = "turn \"We\";})(),(function fuck(){return \"IOs\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"DRx\";})()," ascii
    $s2 = "return \"Wo0\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"Na\";})(),(function fuck(){return \"USf\";})()" ascii
    $s3 = "{return \"TTs\";})(),(function fuck(){return \"We\";})(),(function fuck(){return \"Jg\";})(),(function fuck(){return \"AUx\";})(" ascii
    $s4 = ",(function fuck(){return \"AUx\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){" ascii
    $s5 = "nction fuck(){return \"RAi\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){ret" ascii
    $s6 = "{return \"Wo0\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"Na\";})(),(function fuck(){return \"USf\";})(" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}