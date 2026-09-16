rule _20160921_6c49e33f1abb3ca2b0ff12a4878e38c8_20160921_91734b00fd54_3880 {
  meta:
    description = "datamaliciousorder - from files 20160921_6c49e33f1abb3ca2b0ff12a4878e38c8.js, 20160921_91734b00fd54cd3dd10c5f20c35d7864.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b2c5f6e5a1ebce2cb0eb54f0d28ea21ab88b07dc646376bb3fc5ce29af1615aa"
    hash2       = "cdae8af0c395dfe20c83f759c05d2fd6ae2859606871798c6b3a7a12257c7f70"

  strings:
    $s1 = "k(){return \"Yk\";})(),(function fuck(){return \"IOs\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"MOj\";" ascii
    $s2 = "\"Jo\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ml\";})(),(funct" ascii
    $s3 = "ction fuck(){return \"LGo\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){retu" ascii
    $s4 = "nction fuck(){return \"NKq\";})(),(function fuck(){return \"CTm\";})(),(function fuck(){return \"CTm\";})(),(function fuck(){ret" ascii
    $s5 = "return \"Py\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"MOj\";})(" ascii
    $s6 = "){return \"CTm\";})(),(function fuck(){return \"GJx\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"MUs\";}" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}