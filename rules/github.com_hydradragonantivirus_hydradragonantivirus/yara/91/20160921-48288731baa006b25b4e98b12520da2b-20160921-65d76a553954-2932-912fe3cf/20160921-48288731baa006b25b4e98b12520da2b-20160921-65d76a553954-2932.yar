rule _20160921_48288731baa006b25b4e98b12520da2b_20160921_65d76a553954_2932 {
  meta:
    description = "datamaliciousorder - from files 20160921_48288731baa006b25b4e98b12520da2b.js, 20160921_65d76a5539546b98145997b9a44c1a09.js, 20160921_af22e174703ebae0fa1368fd471dba37.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ce917015afcf31459cc47b8864f85394a756701f6338f6a2cbe079779c3ecd43"
    hash2       = "0a1b81d7435f521382a4cec07d80cbc8fe75f2ebac92fb6c4d105b19ec098560"
    hash3       = "24c1540f49c4fe83a182058f70751619567afa9e8884c1dee7ae13e5fad14a59"

  strings:
    $s1 = "uck(){return \"Pc\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"Mw\";})(),(function fuck(){return \"Yk\";" ascii
    $s2 = " \"UOe\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"MOj\";})(),(func" ascii
    $s3 = "nction fuck(){return \"Mw\";})(),(function fuck(){return \"Jh\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return" ascii
    $s4 = "urn \"Xg\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"IPu\";})(),(" ascii
    $s5 = "),(function fuck(){return \"Ik\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return \"KVh\";})(),(function fuck(){" ascii
    $s6 = "})(),(function fuck(){return \"GJx\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return \"Ar\";})(),(function fuck" ascii
    $s7 = " fuck(){return \"MBg\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}