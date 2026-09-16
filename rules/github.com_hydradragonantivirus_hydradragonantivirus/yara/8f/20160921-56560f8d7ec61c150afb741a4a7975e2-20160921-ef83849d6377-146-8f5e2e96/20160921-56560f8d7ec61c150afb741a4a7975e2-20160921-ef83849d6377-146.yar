rule _20160921_56560f8d7ec61c150afb741a4a7975e2_20160921_ef83849d6377_146 {
  meta:
    description = "datamaliciousorder - from files 20160921_56560f8d7ec61c150afb741a4a7975e2.js, 20160921_ef83849d63779003debb3d7ec32b193e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ba922e4e746eb45b8e98a88ec3071072c0850dbd5e2a359302331e1ae65210fb"
    hash2       = "8c488afd3d971ee89eb15305d884bacb01b91fa70760bea0aaf808120622dfa3"

  strings:
    $s1  = "n \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Oh\";})(),(function fuck(){return \"XCr\";})(),(fu" ascii
    $s2  = "\"Wo0\";})(),(function fuck(){return \"SUi\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"IPu\";})(),(fun" ascii
    $s3  = "})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"MOj\";})(),(function fuc" ascii
    $s4  = "eturn \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"KVh\";})()" ascii
    $s5  = "fuck(){return \"IPu\";})(),(function fuck(){return \"Wo0\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"DR" ascii
    $s6  = "(),(function fuck(){return \"XFd\";})(),(function fuck(){return \"DAa\";})(),(function fuck(){return \"PDf\";})(),(function fuck" ascii
    $s7  = "tion fuck(){return \"IOs\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return" ascii
    $s8  = "KVh\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"Ug\";})(),(function fuck(){return \"Bz\";})(),(functio" ascii
    $s9  = "ction fuck(){return \"IPu\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){retu" ascii
    $s10 = "Us\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"YQt\";})(),(functio" ascii
    $s11 = "d\";})(),(function fuck(){return \"Jg\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"MOj\";})(),(function" ascii
    $s12 = "ck(){return \"IPu\";})(),(function fuck(){return \"Oh\";})(),(function fuck(){return \"We\";})(),(function fuck(){return \"Ar\";" ascii
    $s13 = "turn \"UXf\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"DWe\";})(),(function fuck(){return \"Yk\";})()," ascii
    $s14 = "return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"XHj\";})(" ascii
    $s15 = "ion fuck(){return \"XHj\";})(),(function fuck(){return \"FJs\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return" ascii
    $s16 = "return \"UOe\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";})" ascii
    $s17 = "{return \"MUs\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";}" ascii
    $s18 = "){return \"Xw\";})(),(function fuck(){return \"LLv\";})(),(function fuck(){return \"DHd\";})(),(function fuck(){return \"Xw\";})" ascii
    $s19 = " fuck(){return \"GWo\";})(),(function fuck(){return \"DAa\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"D" ascii
    $s20 = "(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"KVh\";})(),(function fuck(){return \"IPu\";})(),(function fuck" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}