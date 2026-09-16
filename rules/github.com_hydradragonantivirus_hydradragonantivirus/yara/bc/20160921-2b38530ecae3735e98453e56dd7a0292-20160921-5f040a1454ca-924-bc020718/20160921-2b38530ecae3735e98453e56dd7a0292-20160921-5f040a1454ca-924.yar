rule _20160921_2b38530ecae3735e98453e56dd7a0292_20160921_5f040a1454ca_924 {
  meta:
    description = "datamaliciousorder - from files 20160921_2b38530ecae3735e98453e56dd7a0292.js, 20160921_5f040a1454cafc62100cb4449da0b7e2.js, 20160921_5fbbbcb8f403a68df153b90d52e5fff9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "46f1595f803e301ed13d99315b244aac664f908c0c0d8ab508c1d104bf7ae947"
    hash2       = "0ffb0f3f8e3e8ace2b8b6c1bccf53c8b5a11fd2ed00ff3b54971e8b0ca5e139d"
    hash3       = "1e2661f95b6bb745bac719b1313cfa9a489ecd857f66bfe9fe5398391e372ca4"

  strings:
    $s1  = "return \"Xg\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"GJx\";})(" ascii
    $s2  = "ion fuck(){return \"USf\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return " ascii
    $s3  = ",(function fuck(){return \"OQr\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){r" ascii
    $s4  = "ZLd\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"GWo\";})(),(function fuck(){return \"MOj\";})(),(functi" ascii
    $s5  = "{return \"UXf\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){return \"Qh\";})(" ascii
    $s6  = "fuck(){return \"USf\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"F" ascii
    $s7  = " fuck(){return \"Ai\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return \"MB" ascii
    $s8  = "uck(){return \"IRn\";})(),(function fuck(){return \"IKv\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"IRn" ascii
    $s9  = "k(){return \"Sx\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"RAi\"" ascii
    $s10 = " fuck(){return \"Py\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"NK" ascii
    $s11 = "turn \"IRn\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"Py\";})(),(" ascii
    $s12 = "ion fuck(){return \"AUx\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return " ascii
    $s13 = "unction fuck(){return \"UOe\";})(),(function fuck(){return \"OPz\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){re" ascii
    $s14 = "tion fuck(){return \"IPu\";})(),(function fuck(){return \"Oh\";})(),(function fuck(){return \"We\";})(),(function fuck(){return " ascii
    $s15 = "rn \"Dc\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"Py\";})(),(fun" ascii
    $s16 = "function fuck(){return \"Bz\";})(),(function fuck(){return \"CTm\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){ret" ascii
    $s17 = "d\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"CCb\";})(),(functio" ascii
    $s18 = "n \"IPu\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"MUs\";})(),(fun" ascii
    $s19 = "n fuck(){return \"IPu\";})(),(function fuck(){return \"Cs\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"" ascii
    $s20 = "eturn \"USf\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"Bz\";})()" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}