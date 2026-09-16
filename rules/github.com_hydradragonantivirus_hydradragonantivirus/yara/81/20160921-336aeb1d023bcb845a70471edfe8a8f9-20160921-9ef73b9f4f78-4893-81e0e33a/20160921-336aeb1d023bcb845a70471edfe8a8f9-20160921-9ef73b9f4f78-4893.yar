rule _20160921_336aeb1d023bcb845a70471edfe8a8f9_20160921_9ef73b9f4f78_4893 {
  meta:
    description = "datamaliciousorder - from files 20160921_336aeb1d023bcb845a70471edfe8a8f9.js, 20160921_9ef73b9f4f78d9ac2f908b3cdd8db13d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f77fe3497bb26b47e909d597cb0055c997e8149b22c878594ee85d0303c27381"
    hash2       = "31bd1528e102f576486e80b1ead7224fc04db7a81b4fbf1ae11c4416b5e4bd57"

  strings:
    $s1 = "(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"Wo0\";})(),(function fuck(" ascii
    $s2 = "ck(){return \"ZLd\";})(),(function fuck(){return \"YAv\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx" ascii
    $s3 = "uck(){return \"GNm\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"We\";})(),(function fuck(){return \"QTc" ascii
    $s4 = "(function fuck(){return \"DRx\";})(),(function fuck(){return \"XCr\";})(),(function fuck(){return \"Na\";})(),(function fuck(){r" ascii
    $s5 = "rn \"ZVi\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"Zy\";})(),(function fuck(){return \"Sx\";})(),(fu" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}