rule _20160921_5a42eec12fd0d8c1d5256852068b87b8_20160921_ae190d4c26ff_3812 {
  meta:
    description = "datamaliciousorder - from files 20160921_5a42eec12fd0d8c1d5256852068b87b8.js, 20160921_ae190d4c26ff954cee57fde04839fdcd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "54a7451a184fd8afa3cac9d787d5f83abeb8fecd14d9f136cff135e9f0d849e0"
    hash2       = "0a337ab3ebbd0c762482045ac2f2536c27fbe1276893efdedbafc2c805709064"

  strings:
    $s1 = "return \"We\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"SUi\";})(),(function fuck(){return \"IPu\";})(" ascii
    $s2 = "tion fuck(){return \"MBg\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"USf\";})(),(function fuck(){retur" ascii
    $s3 = "n \"AUx\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"LGo\";})(),(f" ascii
    $s4 = " fuck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"Wo" ascii
    $s5 = "function fuck(){return \"Ot\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){ret" ascii
    $s6 = "on fuck(){return \"RAi\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return " ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}