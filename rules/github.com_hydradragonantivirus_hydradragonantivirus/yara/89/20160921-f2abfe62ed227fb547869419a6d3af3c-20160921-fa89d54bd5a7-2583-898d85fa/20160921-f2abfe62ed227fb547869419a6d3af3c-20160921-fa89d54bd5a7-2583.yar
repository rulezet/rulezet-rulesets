rule _20160921_f2abfe62ed227fb547869419a6d3af3c_20160921_fa89d54bd5a7_2583 {
  meta:
    description = "datamaliciousorder - from files 20160921_f2abfe62ed227fb547869419a6d3af3c.js, 20160921_fa89d54bd5a7a27defe09d5a56b5a881.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "843cfa29e93bfa9adfe4410735aacbf939d01a404dc3c507c0562f478b65086f"
    hash2       = "30f2a7c2562ef79254c8129be50246b9c41eb24f000c8cfbd0f4f8c28b49b00f"

  strings:
    $s1 = "k\";})(),(function fuck(){return \"EHo\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"MIl\";})(),(functio" ascii
    $s2 = "){return \"TTs\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"DAa\";})(),(function fuck(){return \"IPu\";" ascii
    $s3 = "){return \"XHj\";})(),(function fuck(){return \"GWo\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"OQr\";" ascii
    $s4 = "nction fuck(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Yk\";})(),(function fuck(){retu" ascii
    $s5 = "nction fuck(){return \"XCr\";})(),(function fuck(){return \"KVh\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){ret" ascii
    $s6 = "ion fuck(){return \"Qh\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return " ascii
    $s7 = "ction fuck(){return \"Sx\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){retur" ascii
    $s8 = "){return \"Jg\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"XFd\";}" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}