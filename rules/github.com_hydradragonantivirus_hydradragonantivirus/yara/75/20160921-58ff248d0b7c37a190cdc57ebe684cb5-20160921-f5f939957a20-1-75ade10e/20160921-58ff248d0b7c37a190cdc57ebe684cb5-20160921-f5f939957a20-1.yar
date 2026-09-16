rule _20160921_58ff248d0b7c37a190cdc57ebe684cb5_20160921_f5f939957a20_1 {
  meta:
    description = "datamaliciousorder - from files 20160921_58ff248d0b7c37a190cdc57ebe684cb5.js, 20160921_f5f939957a207b333a934a05633cece9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5efb6baa739ffd0f8f52557bb0001c41c5ce67360386768dd6544cc9e3ff6409"
    hash2       = "fac44d1f82da41898564ed38982f03fb3c05a688e5205660ae593449d4e5530e"

  strings:
    $s1  = "eturn \"MBg\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"XFd\";})(" ascii
    $s2  = "return \"Xw\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"FJs\";})(),(function fuck(){return \"Xw\";})()," ascii
    $s3  = "uck(){return \"Vf\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"IPu" ascii
    $s4  = "nction fuck(){return \"IPu\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"GWo\";})(),(function fuck(){ret" ascii
    $s5  = "s\";})(),(function fuck(){return \"Wo0\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function" ascii
    $s6  = "ion fuck(){return \"USf\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Et\";})(),(function fuck(){return " ascii
    $s7  = "function fuck(){return \"Vb\";})(),(function fuck(){return \"CCb\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){re" ascii
    $s8  = "n \"LGo\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"IRn\";})(),(fu" ascii
    $s9  = "{return \"GNm\";})(),(function fuck(){return \"Bz\";})(),(function fuck(){return \"CTm\";})(),(function fuck(){return \"PDf\";})" ascii
    $s10 = "\"CCb\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"MBg\";})(),(fun" ascii
    $s11 = "),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"Zy\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){" ascii
    $s12 = "unction fuck(){return \"Py\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){ret" ascii
    $s13 = "unction fuck(){return \"UOe\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){ret" ascii
    $s14 = "n fuck(){return \"XFd\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return " ascii
    $s15 = " fuck(){return \"LGo\";})(),(function fuck(){return \"CCb\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"" ascii
    $s16 = "rn \"CCb\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"LGo\";})(),(" ascii
    $s17 = "Rx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"QTc\";})(),(functio" ascii
    $s18 = "unction fuck(){return \"CCb\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){re" ascii
    $s19 = "n \"IPu\";})(),(function fuck(){return \"ZLd\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"SUi\";})(),(fu" ascii
    $s20 = "(){return \"AUx\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"RAi\";" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}