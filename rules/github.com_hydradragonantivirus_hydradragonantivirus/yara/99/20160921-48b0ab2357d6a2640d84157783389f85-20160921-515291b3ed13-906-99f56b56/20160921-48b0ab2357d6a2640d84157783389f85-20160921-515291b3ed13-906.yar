rule _20160921_48b0ab2357d6a2640d84157783389f85_20160921_515291b3ed13_906 {
  meta:
    description = "datamaliciousorder - from files 20160921_48b0ab2357d6a2640d84157783389f85.js, 20160921_515291b3ed13de9fe2933a326bc71920.js, 20160921_f5230fc58405f25233bda6815654bd6e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fee375f08ae5432a47f4a4a8fefed2cbbb6e1484d8914742942e60f703c8f7f0"
    hash2       = "6deef7cfd2f4743f897d0043907a6481545f6a96b01c76c7d81d02348a2a17e0"
    hash3       = "1a813dda7d0088c45bb00563ea79982995ec1337c805380117fe705f80c51c64"

  strings:
    $s1  = " fuck(){return \"Et\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"MO" ascii
    $s2  = ",(function fuck(){return \"TTs\";})(),(function fuck(){return \"Ug\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){r" ascii
    $s3  = "){return \"EHo\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";}" ascii
    $s4  = "n fuck(){return \"MBg\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"" ascii
    $s5  = "Yk\";})(),(function fuck(){return \"GJx\";})(),(function fuck(){return \"Mw\";})(),(function fuck(){return \"IPu\";})(),(functio" ascii
    $s6  = "DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"Nm\";})(),(functio" ascii
    $s7  = "){return \"Yk\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"Na\";})(),(function fuck(){return \"Py\";})()" ascii
    $s8  = "Py\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"Ot\";})(),(functio" ascii
    $s9  = "function fuck(){return \"Cd\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){re" ascii
    $s10 = "uck(){return \"Mw\";})(),(function fuck(){return \"Jh\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"Za\";" ascii
    $s11 = "eturn \"Et\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"Mw\";})(),(function fuck(){return \"MOj\";})(),(" ascii
    $s12 = "){return \"AUx\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"Cd\";}" ascii
    $s13 = " fuck(){return \"OQr\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){return \"" ascii
    $s14 = "})(),(function fuck(){return \"UXf\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"MOj\";})(),(function fuc" ascii
    $s15 = "ction fuck(){return \"IPu\";})(),(function fuck(){return \"We\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return" ascii
    $s16 = "\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"Jg\";})(),(function fuck(){return \"Vb\";})(),(function fu" ascii
    $s17 = "){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"We\";})(),(function fuck(){return \"IOs\";}" ascii
    $s18 = "ction fuck(){return \"AUx\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"DWe\";})(),(function fuck(){retu" ascii
    $s19 = "ion fuck(){return \"OQr\";})(),(function fuck(){return \"Et\";})(),(function fuck(){return \"CCb\";})(),(function fuck(){return " ascii
    $s20 = "ction fuck(){return \"IPu\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){retu" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}