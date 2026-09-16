rule _20160921_4b7874934ca20c6643210a0c92fe260f_20160921_be4748da0160_5103 {
  meta:
    description = "datamaliciousorder - from files 20160921_4b7874934ca20c6643210a0c92fe260f.js, 20160921_be4748da01602fdf2d9ffd03054028e4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "858cb8ac4dab1ec1e6a2a0bb435765157525269e75820991212eee18a2d91717"
    hash2       = "4847889a558b3e0b60d671ec5082e36330f771c8789f9ae89683bf49e7128616"

  strings:
    $s1 = "){return \"YQt\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"Ug\";}" ascii
    $s2 = " \"IPu\";})(),(function fuck(){return \"IKv\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"YQt\";})(),(fu" ascii
    $s3 = ")(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"YQt\";})(),(function fuc" ascii
    $s4 = "),(function fuck(){return \"ADy\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"NKq\";})(),(function fuck(" ascii
    $s5 = "{return \"TTs\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"YQt\";}" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}