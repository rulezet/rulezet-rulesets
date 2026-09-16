rule _20160921_7c5b5eaba938fa91eb6a9414212e13f9_20160921_884f773b3c24_1607 {
  meta:
    description = "datamaliciousorder - from files 20160921_7c5b5eaba938fa91eb6a9414212e13f9.js, 20160921_884f773b3c246c835029fc91499fb017.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9b25331c24a00cfccf7bf1604f7df1d245543734bf5553f0a7c3c911bb74cbb8"
    hash2       = "4523d83a689974fc97f79b6c7c440d4b9f2a13825d1b664954798d786c1e2609"

  strings:
    $s1  = "ZWu\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"IPu\";})(),(functio" ascii
    $s2  = "b\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"IRn\";})(),(function " ascii
    $s3  = "k(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"Sx\"" ascii
    $s4  = "){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Oh\";})(),(function fuck(){return \"Sx\";})" ascii
    $s5  = "ion fuck(){return \"Np\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return " ascii
    $s6  = "tion fuck(){return \"IPu\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return" ascii
    $s7  = ")(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"Vb\";})(),(function fuck(" ascii
    $s8  = "z\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"Ve\";})(),(function " ascii
    $s9  = " \"MUs\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"OQr\";})(),(fu" ascii
    $s10 = "return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"We\";})(),(function fuck(){return \"Sx\";})()" ascii
    $s11 = "ck(){return \"MBg\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"FJs" ascii
    $s12 = "return \"XHj\";})(),(function fuck(){return \"Wo0\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";})" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}