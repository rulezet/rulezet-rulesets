rule _20160921_30902cdec8afbffc64d0c0cd57e17570_20160921_c58f55b02ed5_126 {
  meta:
    description = "datamaliciousorder - from files 20160921_30902cdec8afbffc64d0c0cd57e17570.js, 20160921_c58f55b02ed5bcc68d14314fe1cbe1f0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "794f51b8ce9ffbf2858ed5522e027d4ca3155be961907d88f09dd5679b3f1a18"
    hash2       = "9b14dd6c2f6263aca7c445e6160fdf64ae8e12248f26b67576668dd3b4f18382"

  strings:
    $s1  = "),(function fuck(){return \"TTs\";})(),(function fuck(){return \"CCb\";})(),(function fuck(){return \"Jh\";})(),(function fuck()" ascii
    $s2  = "urn \"Hs\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"DAa\";})(),(function fuck(){return \"DRx\";})(),(f" ascii
    $s3  = "Pu\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){return \"Ar\";})(),(function fuck(){return \"Np\";})(),(function " ascii
    $s4  = "n \"Jo\";})(),(function fuck(){return \"ZVi\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"IPu\";})(),(fun" ascii
    $s5  = "n \"OPz\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"Zy\";})(),(fun" ascii
    $s6  = ",(function fuck(){return \"IPu\";})(),(function fuck(){return \"XCr\";})(),(function fuck(){return \"Ar\";})(),(function fuck(){" ascii
    $s7  = "rn \"Jg\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MBg\";})(),(f" ascii
    $s8  = "on fuck(){return \"LGo\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return " ascii
    $s9  = "ction fuck(){return \"Xw\";})(),(function fuck(){return \"KVh\";})(),(function fuck(){return \"FJs\";})(),(function fuck(){retur" ascii
    $s10 = "nction fuck(){return \"Mw\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"CCb\";})(),(function fuck(){retu" ascii
    $s11 = "k(){return \"TTs\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"KVh\";" ascii
    $s12 = "\"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Yk\";})(),(function fuck(){return \"Nm\";})(),(funct" ascii
    $s13 = "rn \"IPu\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"FJs\";})(),(function fuck(){return \"Xw\";})(),(fu" ascii
    $s14 = "rn \"Jg\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"NKq\";})(),(fu" ascii
    $s15 = "n fuck(){return \"YAv\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return " ascii
    $s16 = "uck(){return \"Xw\";})(),(function fuck(){return \"DHd\";})(),(function fuck(){return \"DHd\";})(),(function fuck(){return \"Ik" ascii
    $s17 = "k(){return \"GNm\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"LLv" ascii
    $s18 = "x\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"GWo\";})(),(function fuck(){return \"FJs\";})(),(functio" ascii
    $s19 = "})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"XCr\";})(),(function fu" ascii
    $s20 = "uck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DWe\";})(),(function fuck(){return \"CCb" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}