rule _20160921_18eedffe02de43ba2ee494451deba790_20160921_1e5a9eb0eb0b_45 {
  meta:
    description = "datamaliciousorder - from files 20160921_18eedffe02de43ba2ee494451deba790.js, 20160921_1e5a9eb0eb0b79e733771c60a3c09d60.js, 20160921_46f76411edda6b812c8adc67d2ad383c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "295460c559aa147e2ea748501c56677647c72b71ee7df9051801008304580029"
    hash2       = "fb9f71807b6b8b0f0dea01eb8e6e4eef0c54c22c99493c5825b4acb828c2e8b1"
    hash3       = "f72be114af5c43c1d1df32b679c547b8e87512e78385118e9bcd668bc660230a"

  strings:
    $s1  = "Rx\";})(),(function fuck(){return \"We\";})(),(function fuck(){return \"DAa\";})(),(function fuck(){return \"LGo\";})(),(functio" ascii
    $s2  = "(){return \"IKv\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"UOe\"" ascii
    $s3  = "k(){return \"Cd\";})(),(function fuck(){return \"OPz\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Cd\";" ascii
    $s4  = "urn \"Xg\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"OPz\";})(),(function fuck(){return \"IPu\";})(),(" ascii
    $s5  = "function fuck(){return \"MBg\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"Zy\";})(),(function fuck(){re" ascii
    $s6  = "){return \"Bz\";})(),(function fuck(){return \"Tv\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"IPu\";})" ascii
    $s7  = "fuck(){return \"TTs\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"RA" ascii
    $s8  = " \"Ve\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"Ug\";})(),(func" ascii
    $s9  = "\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"Vb\";})(),(function f" ascii
    $s10 = "tion fuck(){return \"CTm\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return" ascii
    $s11 = "unction fuck(){return \"XCr\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"Jg\";})(),(function fuck(){ret" ascii
    $s12 = "(){return \"LGo\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"IPu\"" ascii
    $s13 = "uck(){return \"Za\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx" ascii
    $s14 = "rn \"Ar\";})(),(function fuck(){return \"KVh\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return \"Ik\";})(),(fu" ascii
    $s15 = " \"IPu\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"MIl\";})(),(function fuck(){return \"QTc\";})(),(fun" ascii
    $s16 = "n \"TTs\";})(),(function fuck(){return \"To\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"Vb\";})(),(fun" ascii
    $s17 = "k(){return \"FJs\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"ZLd" ascii
    $s18 = " \"Mw\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"YQt\";})(),(func" ascii
    $s19 = "k(){return \"We\";})(),(function fuck(){return \"ZVi\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"TTs\";" ascii
    $s20 = "urn \"Jo\";})(),(function fuck(){return \"Et\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"IPu\";})(),(fu" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}