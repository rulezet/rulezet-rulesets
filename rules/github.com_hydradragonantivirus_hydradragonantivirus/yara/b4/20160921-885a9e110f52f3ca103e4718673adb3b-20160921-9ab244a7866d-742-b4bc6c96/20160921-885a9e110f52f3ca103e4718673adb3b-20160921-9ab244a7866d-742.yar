rule _20160921_885a9e110f52f3ca103e4718673adb3b_20160921_9ab244a7866d_742 {
  meta:
    description = "datamaliciousorder - from files 20160921_885a9e110f52f3ca103e4718673adb3b.js, 20160921_9ab244a7866dc1a3d98006482dd7da38.js, 20160921_f926399cbb634492c58e195c86a0bbde.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a777a2e324ff6d64746b42793d888cea6f2beec30ded4165b5b13eda473e58bf"
    hash2       = "99692f93901b579e0992cf6f44c274569bb1257cf12f2eebf5baceb7cb31d6af"
    hash3       = "15b29ae0204a4b512f15931b197f4e0ddaad99fc24c68356f1631bedc62dcac6"

  strings:
    $s1  = ",(function fuck(){return \"XCr\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){r" ascii
    $s2  = "k(){return \"To\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MBg\";" ascii
    $s3  = "Pu\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return \"PDf\";})(),(functio" ascii
    $s4  = "fuck(){return \"XCr\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return \"IPu" ascii
    $s5  = "\"LGo\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"IPu\";})(),(func" ascii
    $s6  = "on fuck(){return \"IPu\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return " ascii
    $s7  = "return \"IPu\";})(),(function fuck(){return \"GJx\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"GNm\";})(" ascii
    $s8  = "ck(){return \"Xw\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"Xw\";" ascii
    $s9  = "ck(){return \"IPu\";})(),(function fuck(){return \"GJx\";})(),(function fuck(){return \"QTc\";})(),(function fuck(){return \"IPu" ascii
    $s10 = "){return \"IPu\";})(),(function fuck(){return \"GWo\";})(),(function fuck(){return \"Mw\";})(),(function fuck(){return \"USf\";}" ascii
    $s11 = "n fuck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"O" ascii
    $s12 = "return \"ZWu\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"Np\";})()," ascii
    $s13 = "return \"Ot\";})(),(function fuck(){return \"QTc\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"OPz\";})()" ascii
    $s14 = "eturn \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"YAv\";})()," ascii
    $s15 = "){return \"IPu\";})(),(function fuck(){return \"GWo\";})(),(function fuck(){return \"Ar\";})(),(function fuck(){return \"IPu\";}" ascii
    $s16 = "n fuck(){return \"USf\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"" ascii
    $s17 = " fuck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Yk\";})(),(function fuck(){return \"Fv" ascii
    $s18 = "Ux\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";})(),(functio" ascii
    $s19 = "ion fuck(){return \"Sx\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"Yk\";})(),(function fuck(){return " ascii
    $s20 = "k(){return \"IPu\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"PDf\";" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}