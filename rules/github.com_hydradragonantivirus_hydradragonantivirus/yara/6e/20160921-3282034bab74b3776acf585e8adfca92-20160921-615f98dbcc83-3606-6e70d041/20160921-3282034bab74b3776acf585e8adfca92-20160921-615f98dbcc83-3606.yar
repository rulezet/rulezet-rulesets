rule _20160921_3282034bab74b3776acf585e8adfca92_20160921_615f98dbcc83_3606 {
  meta:
    description = "datamaliciousorder - from files 20160921_3282034bab74b3776acf585e8adfca92.js, 20160921_615f98dbcc83e57c9789ba9d89e188d0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0b99efa289490e150d7af72ae3e0fb067880b4a22c16ba75dec34f9945b5c2df"
    hash2       = "3ee4da5f56533720f6cb24f55125aadc635f7464c5c8a7fbc14e3949f44d0ee5"

  strings:
    $s1 = "(function fuck(){return \"LGo\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"USf\";})(),(function fuck(){r" ascii
    $s2 = ")(),(function fuck(){return \"CCb\";})(),(function fuck(){return \"Mw\";})(),(function fuck(){return \"Ve\";})(),(function fuck(" ascii
    $s3 = "ck(){return \"ZWu\";})(),(function fuck(){return \"CCb\";})(),(function fuck(){return \"Ar\";})(),(function fuck(){return \"IPu" ascii
    $s4 = "ck(){return \"Ar\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"MOj\"" ascii
    $s5 = "rn \"Xg\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"GJx\";})(),(function fuck(){return \"Ik\";})(),(fun" ascii
    $s6 = "(function fuck(){return \"IPu\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"Wo0\";})(),(function fuck(){" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}