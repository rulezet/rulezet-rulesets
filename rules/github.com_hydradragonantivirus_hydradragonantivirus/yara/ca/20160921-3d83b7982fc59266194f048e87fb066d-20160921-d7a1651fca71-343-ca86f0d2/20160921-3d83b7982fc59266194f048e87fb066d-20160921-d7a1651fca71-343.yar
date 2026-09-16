rule _20160921_3d83b7982fc59266194f048e87fb066d_20160921_d7a1651fca71_343 {
  meta:
    description = "datamaliciousorder - from files 20160921_3d83b7982fc59266194f048e87fb066d.js, 20160921_d7a1651fca7129364bbe9da7195a89dc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f14778492463eaa86aec448221dcd9e88defb1f42404b2b80d42b0d0c41ffa66"
    hash2       = "2c37b7e410e05a2e285f2d4909012cdefffdcc0d9e06b06aafce7aba5b9684f6"

  strings:
    $s1  = "function fuck(){return \"ZLd\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"Av\";})(),(function fuck(){ret" ascii
    $s2  = "Hs\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"Py\";})(),(function" ascii
    $s3  = "MBg\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"Vb\";})(),(functi" ascii
    $s4  = "uck(){return \"TTs\";})(),(function fuck(){return \"IKv\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"Hs" ascii
    $s5  = "ion fuck(){return \"LGo\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return " ascii
    $s6  = "fuck(){return \"Vb\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"NKq" ascii
    $s7  = "n fuck(){return \"UOe\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"" ascii
    $s8  = "fuck(){return \"IKv\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"Hs" ascii
    $s9  = " \"TTs\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"Jo\";})(),(func" ascii
    $s10 = " \"LGo\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"Np\";})(),(funct" ascii
    $s11 = "\"Py\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"We\";})(),(functi" ascii
    $s12 = "k(){return \"Py\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";" ascii
    $s13 = " \"TTs\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"Py\";})(),(fun" ascii
    $s14 = "return \"LGo\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"NKq\";})()" ascii
    $s15 = "urn \"IKv\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"Py\";})(),(f" ascii
    $s16 = "k(){return \"Za\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\"" ascii
    $s17 = "p\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"Ug\";})(),(function" ascii
    $s18 = "eturn \"GWo\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"GNm\";})(" ascii
    $s19 = " fuck(){return \"ADy\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"I" ascii
    $s20 = "ck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"Ai\"" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}