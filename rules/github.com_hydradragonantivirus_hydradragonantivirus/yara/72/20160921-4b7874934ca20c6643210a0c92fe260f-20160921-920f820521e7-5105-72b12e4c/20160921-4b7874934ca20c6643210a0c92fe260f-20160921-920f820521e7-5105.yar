rule _20160921_4b7874934ca20c6643210a0c92fe260f_20160921_920f820521e7_5105 {
  meta:
    description = "datamaliciousorder - from files 20160921_4b7874934ca20c6643210a0c92fe260f.js, 20160921_920f820521e7af7d81b11e9545080390.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "858cb8ac4dab1ec1e6a2a0bb435765157525269e75820991212eee18a2d91717"
    hash2       = "c4a6a94fe43f214f35574405d899a6d61259c2b1135c1ecf399630de11c6dea3"

  strings:
    $s1 = ",(function fuck(){return \"MBg\";})(),(function fuck(){return \"IKv\";})(),(function fuck(){return \"AUx\";})(),(function fuck()" ascii
    $s2 = "rn \"MBg\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Yk\";})(),(function fuck(){return \"EHo\";})(),(f" ascii
    $s3 = " fuck(){return \"IPu\";})(),(function fuck(){return \"Cs\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"E" ascii
    $s4 = "n \"TTs\";})(),(function fuck(){return \"Et\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"FJs\";})(),(fu" ascii
    $s5 = "),(function fuck(){return \"Wo0\";})(),(function fuck(){return \"GWo\";})(),(function fuck(){return \"IPu\";})(),(function fuck(" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}