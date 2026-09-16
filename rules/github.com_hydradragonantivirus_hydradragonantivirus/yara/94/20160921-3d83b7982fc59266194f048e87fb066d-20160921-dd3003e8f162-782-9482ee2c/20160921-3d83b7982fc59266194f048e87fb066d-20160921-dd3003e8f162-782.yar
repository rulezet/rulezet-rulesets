rule _20160921_3d83b7982fc59266194f048e87fb066d_20160921_dd3003e8f162_782 {
  meta:
    description = "datamaliciousorder - from files 20160921_3d83b7982fc59266194f048e87fb066d.js, 20160921_dd3003e8f16270410cd847da3878f1fc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f14778492463eaa86aec448221dcd9e88defb1f42404b2b80d42b0d0c41ffa66"
    hash2       = "484cc3f4c9cc3a29ae3ad53bb6d47be99d119531836a636c664a77fc891b38fc"

  strings:
    $s1  = "ion fuck(){return \"Fv\";})(),(function fuck(){return \"QTc\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return " ascii
    $s2  = "a\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"NKq\";})(),(function" ascii
    $s3  = "{return \"IPu\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){return \"ZVi\";})(),(function fuck(){return \"USf\";}" ascii
    $s4  = "),(function fuck(){return \"Ar\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"IRn\";})(),(function fuck()" ascii
    $s5  = "nction fuck(){return \"UOe\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"Py\";})(),(function fuck(){retu" ascii
    $s6  = "urn \"LGo\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"GNm\";})(),(" ascii
    $s7  = "eturn \"Py\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"IPu\";})()," ascii
    $s8  = "return \"Hs\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"CTm\";})(" ascii
    $s9  = ";})(),(function fuck(){return \"CTm\";})(),(function fuck(){return \"Oh\";})(),(function fuck(){return \"Jh\";})(),(function fuc" ascii
    $s10 = ";})(),(function fuck(){return \"Ug\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return \"YAv\";})(),(function fuc" ascii
    $s11 = "eturn \"Cd\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"MBg\";})()" ascii
    $s12 = "(){return \"XHj\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"IRn\";}" ascii
    $s13 = "ction fuck(){return \"IPu\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"USf\";})(),(function fuck(){retu" ascii
    $s14 = "ction fuck(){return \"LGo\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){retur" ascii
    $s15 = "(){return \"LGo\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"IPu\";" ascii
    $s16 = "ck(){return \"Nm\";})(),(function fuck(){return \"Wo0\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MBg" ascii
    $s17 = "x\";})(),(function fuck(){return \"DAa\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";})(),(functio" ascii
    $s18 = "uck(){return \"TTs\";})(),(function fuck(){return \"ZLd\";})(),(function fuck(){return \"Ug\";})(),(function fuck(){return \"UXf" ascii
    $s19 = "on fuck(){return \"IPu\";})(),(function fuck(){return \"Tv\";})(),(function fuck(){return \"Oh\";})(),(function fuck(){return \"" ascii
    $s20 = " \"Nm\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return \"IRn\";})(),(func" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}