rule _20160921_1a47c8a8ea95b60eabaed27e984edacd_20160921_5cabcf77c626_1670 {
  meta:
    description = "datamaliciousorder - from files 20160921_1a47c8a8ea95b60eabaed27e984edacd.js, 20160921_5cabcf77c626e288d5cbd9104a914ae8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b5a5f062c9d94508668ecb987b9d855fefbcdb1cf10f3efded37c21fc6893b0c"
    hash2       = "9493e4251106014081e4b141c6296c51b00c9ba7a799bcb978ea6226cd127d34"

  strings:
    $s1  = "turn \"Jh\";})(),(function fuck(){return \"QTc\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return \"YAv\";})(),(" ascii
    $s2  = "){return \"KVh\";})(),(function fuck(){return \"Jg\";})(),(function fuck(){return \"Ar\";})(),(function fuck(){return \"Fv\";})(" ascii
    $s3  = " \"Pc\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"Ik\";})(),(functi" ascii
    $s4  = "ction fuck(){return \"Hs\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){retur" ascii
    $s5  = "(){return \"IPu\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"Zy\";})(),(function fuck(){return \"SUi\";}" ascii
    $s6  = "function fuck(){return \"Fv\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){re" ascii
    $s7  = "tion fuck(){return \"ZWu\";})(),(function fuck(){return \"Et\";})(),(function fuck(){return \"Jg\";})(),(function fuck(){return " ascii
    $s8  = "ion fuck(){return \"Ik\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"" ascii
    $s9  = " fuck(){return \"Xg\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"V" ascii
    $s10 = "n \"MOj\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Oh\";})(),(function fuck(){return \"XHj\";})(),(fu" ascii
    $s11 = "(),(function fuck(){return \"Yb\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Jo\";})(),(function fuck()" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}