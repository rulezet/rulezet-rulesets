rule _20160921_44880573519212a90b7d910319fc31d8_20160921_4fa304d7c11d_5060 {
  meta:
    description = "datamaliciousorder - from files 20160921_44880573519212a90b7d910319fc31d8.js, 20160921_4fa304d7c11deb5fb9cd6514d5a983de.js, 20160921_7c5b5eaba938fa91eb6a9414212e13f9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8427ee610833efbf68884e3ec13c4357ae35e1aa0bf8ddc2ffe99b9a7f44fb40"
    hash2       = "cef5a1e67f57d9f24065ff0145644e0185df6abc29113310c6782b30e0a9236b"
    hash3       = "9b25331c24a00cfccf7bf1604f7df1d245543734bf5553f0a7c3c911bb74cbb8"

  strings:
    $s1 = " \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){return \"XCr\";})(),(fun" ascii
    $s2 = "),(function fuck(){return \"CCb\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"DRx\";})(),(function fuck()" ascii
    $s3 = "ck(){return \"MUs\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"GNm" ascii
    $s4 = "n \"XHj\";})(),(function fuck(){return \"GJx\";})(),(function fuck(){return \"ZVi\";})(),(function fuck(){return \"Jo\";})(),(fu" ascii
    $s5 = "(function fuck(){return \"SUi\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}