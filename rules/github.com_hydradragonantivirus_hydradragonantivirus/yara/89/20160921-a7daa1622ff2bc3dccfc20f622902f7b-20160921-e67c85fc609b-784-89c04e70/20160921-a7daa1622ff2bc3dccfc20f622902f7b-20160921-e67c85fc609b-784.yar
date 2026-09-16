rule _20160921_a7daa1622ff2bc3dccfc20f622902f7b_20160921_e67c85fc609b_784 {
  meta:
    description = "datamaliciousorder - from files 20160921_a7daa1622ff2bc3dccfc20f622902f7b.js, 20160921_e67c85fc609bef1c06233d9dc655b074.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4caa07134c114c6f14592ae1a6f87a08bd21b6048c96d44b5eb70d9762008059"
    hash2       = "372b553e13a1b2dacf2c8938d6c7953212ff8112978d88f8aa1425ffa2ef21de"

  strings:
    $s1  = "(function fuck(){return \"DAa\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){r" ascii
    $s2  = "ction fuck(){return \"Mw\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Wo\";})(),(function fuck(){return" ascii
    $s3  = "ction fuck(){return \"Ai\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return" ascii
    $s4  = "Cd\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"GNm\";})(),(functi" ascii
    $s5  = "Pu\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"Cd\";})(),(function" ascii
    $s6  = "unction fuck(){return \"CTm\";})(),(function fuck(){return \"Oh\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){ret" ascii
    $s7  = " \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){return \"Ik\";})(),(fun" ascii
    $s8  = "k(){return \"MUs\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"Ai\"" ascii
    $s9  = "ion fuck(){return \"Et\";})(),(function fuck(){return \"Jh\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return " ascii
    $s10 = "on fuck(){return \"Vb\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"" ascii
    $s11 = "k(){return \"UOe\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"Np\";" ascii
    $s12 = ";})(),(function fuck(){return \"CCb\";})(),(function fuck(){return \"Ug\";})(),(function fuck(){return \"UXf\";})(),(function fu" ascii
    $s13 = "){return \"MOj\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Tv\";})(),(function fuck(){return \"Oh\";})" ascii
    $s14 = "rn \"Hs\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";})(),(fu" ascii
    $s15 = "})(),(function fuck(){return \"To\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"IRn\";})(),(function fuck" ascii
    $s16 = "})(),(function fuck(){return \"Cs\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Cd\";})(),(function fuck" ascii
    $s17 = ")(),(function fuck(){return \"Yk\";})(),(function fuck(){return \"Yk\";})(),(function fuck(){return \"ZVi\";})(),(function fuck(" ascii
    $s18 = "Rx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"ZWu\";})(),(functio" ascii
    $s19 = "unction fuck(){return \"Cd\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){ret" ascii
    $s20 = "){return \"IPu\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"Py\";})(" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}