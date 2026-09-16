rule _20160921_11c4976357ef8a651d058575507518ca_20160921_aab5fb25ea89_920 {
  meta:
    description = "datamaliciousorder - from files 20160921_11c4976357ef8a651d058575507518ca.js, 20160921_aab5fb25ea8971982ac223655d50aba2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "aee597813bd24d68729b505b5e718b120274cb1db588f64e61c1a4eb85f6bf11"
    hash2       = "0387ef653c0ac9c5d0aaf638bde80688e7b6b279a435dcab3ff679313abfab3c"

  strings:
    $s1  = "(){return \"Fv\";})(),(function fuck(){return \"QTc\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Ve\";}" ascii
    $s2  = " fuck(){return \"IPu\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"" ascii
    $s3  = "(){return \"LGo\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"MOj\";}" ascii
    $s4  = "\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"We\";})(),(function fuck(){return \"Et\";})(),(function f" ascii
    $s5  = "tion fuck(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MIl\";})(),(function fuck(){retur" ascii
    $s6  = "(function fuck(){return \"Et\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"OPz\";})(),(function fuck(){re" ascii
    $s7  = "eturn \"Vb\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"IPu\";})(),(" ascii
    $s8  = "ction fuck(){return \"Jo\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"DWe\";})(),(function fuck(){retur" ascii
    $s9  = "tion fuck(){return \"Xg\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"Bz\";})(),(function fuck(){return " ascii
    $s10 = "\"UXf\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Vf\";})(),(function fuck(){return \"Ik\";})(),(funct" ascii
    $s11 = ";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"IRn\";})(),(function f" ascii
    $s12 = "fuck(){return \"Jo\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"NK" ascii
    $s13 = "function fuck(){return \"Jo\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"Np\";})(),(function fuck(){ret" ascii
    $s14 = "turn \"We\";})(),(function fuck(){return \"MIl\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"IPu\";})(),(" ascii
    $s15 = "k(){return \"DAa\";})(),(function fuck(){return \"Ar\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"YQt\"" ascii
    $s16 = "DAa\";})(),(function fuck(){return \"Ar\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"Vf\";})(),(functio" ascii
    $s17 = "fuck(){return \"ZWu\";})(),(function fuck(){return \"Yk\";})(),(function fuck(){return \"Ar\";})(),(function fuck(){return \"IPu" ascii
    $s18 = "unction fuck(){return \"KVh\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){re" ascii
    $s19 = "(){return \"Ot\";})(),(function fuck(){return \"Jh\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"IPu\";})" ascii
    $s20 = "ction fuck(){return \"We\";})(),(function fuck(){return \"DAa\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){retur" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}