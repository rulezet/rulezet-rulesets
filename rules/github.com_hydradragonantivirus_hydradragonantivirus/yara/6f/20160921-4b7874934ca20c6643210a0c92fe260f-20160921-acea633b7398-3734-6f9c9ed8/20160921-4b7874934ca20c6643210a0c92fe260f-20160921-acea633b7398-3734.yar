rule _20160921_4b7874934ca20c6643210a0c92fe260f_20160921_acea633b7398_3734 {
  meta:
    description = "datamaliciousorder - from files 20160921_4b7874934ca20c6643210a0c92fe260f.js, 20160921_acea633b73985995ce9764bf94db0972.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "858cb8ac4dab1ec1e6a2a0bb435765157525269e75820991212eee18a2d91717"
    hash2       = "dd77df78b3a755b016a27bbcac8fe7c015ab04472e2ca2d2d9aa476befb3148a"

  strings:
    $s1 = "return \"LGo\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"Ug\";})(" ascii
    $s2 = "AUx\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"Np\";})(),(functi" ascii
    $s3 = "uck(){return \"TTs\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"GNm" ascii
    $s4 = "eturn \"AUx\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"Vb\";})()," ascii
    $s5 = "n \"AUx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ml\";})(),(function fuck(){return \"IPu\";})(),(fu" ascii
    $s6 = "uck(){return \"UOe\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"MB" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}