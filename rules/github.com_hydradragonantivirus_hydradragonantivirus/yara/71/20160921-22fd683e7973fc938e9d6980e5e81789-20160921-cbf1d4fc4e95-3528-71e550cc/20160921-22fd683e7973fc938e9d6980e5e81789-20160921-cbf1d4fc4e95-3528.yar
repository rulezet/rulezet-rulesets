rule _20160921_22fd683e7973fc938e9d6980e5e81789_20160921_cbf1d4fc4e95_3528 {
  meta:
    description = "datamaliciousorder - from files 20160921_22fd683e7973fc938e9d6980e5e81789.js, 20160921_cbf1d4fc4e95f977458908fce0f55adb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c3583ada9b0a35137add948ee4bd3182a5f977a0dbcc3a39c01ee288f703d566"
    hash2       = "de5ba60f48e78004cd5ec7a5ae764a46be1381f19aa87a961c3937fd05a1e2ec"

  strings:
    $s1 = " fuck(){return \"Dc\";})(),(function fuck(){return \"ZVi\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"Hs" ascii
    $s2 = "turn \"IPu\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"FJs\";})(),(function fuck(){return \"Fv\";})(),(" ascii
    $s3 = "\"Xg\";})(),(function fuck(){return \"FJs\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"OQr\";})(),(funct" ascii
    $s4 = "){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return \"Ar\";})" ascii
    $s5 = "ion fuck(){return \"OQr\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return " ascii
    $s6 = "(function fuck(){return \"Jh\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){re" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}