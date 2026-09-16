rule _20160921_8f9ae4533bfbaedf1feae61032904250_20160921_cd62091b5494_54 {
  meta:
    description = "datamaliciousorder - from files 20160921_8f9ae4533bfbaedf1feae61032904250.js, 20160921_cd62091b54940830ea3695d380fd97d8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f093836b93b9b87ed10341ee30bc818ac497c91c6d0dd2b00ab5d3b1822868f9"
    hash2       = "e00553588533d1015b71812c5877864382cbfd2a3a204b4cab76c38ee65ce58c"

  strings:
    $s1  = ")(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"Ug\";})(),(function fuck(" ascii
    $s2  = "ction fuck(){return \"IPu\";})(),(function fuck(){return \"GWo\";})(),(function fuck(){return \"IOs\";})(),(function fuck(){retu" ascii
    $s3  = "on fuck(){return \"To\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return " ascii
    $s4  = "ction fuck(){return \"Xw\";})(),(function fuck(){return \"Mw\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return" ascii
    $s5  = "n fuck(){return \"USf\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return " ascii
    $s6  = " \"IPu\";})(),(function fuck(){return \"Ar\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"Ug\";})(),(func" ascii
    $s7  = "ck(){return \"MUs\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"Jo" ascii
    $s8  = "nction fuck(){return \"IRn\";})(),(function fuck(){return \"IKv\";})(),(function fuck(){return \"USf\";})(),(function fuck(){ret" ascii
    $s9  = "rn \"MBg\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"Vb\";})(),(fu" ascii
    $s10 = "k(){return \"Yk\";})(),(function fuck(){return \"EHo\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\"" ascii
    $s11 = "return \"UXf\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"MIl\";})(" ascii
    $s12 = "eturn \"Wo\";})(),(function fuck(){return \"UXf\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";})()" ascii
    $s13 = "k(){return \"XFd\";})(),(function fuck(){return \"DWe\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return \"IPu\"" ascii
    $s14 = "\"IPu\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"RAi\";})(),(fun" ascii
    $s15 = "urn \"TTs\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"GNm\";})()," ascii
    $s16 = ")(),(function fuck(){return \"Et\";})(),(function fuck(){return \"MIl\";})(),(function fuck(){return \"Py\";})(),(function fuck(" ascii
    $s17 = "{return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"ZVi\";})(" ascii
    $s18 = "ck(){return \"Vb\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"NKq\"" ascii
    $s19 = "){return \"DRx\";})(),(function fuck(){return \"Wo\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){return \"Na\";})(" ascii
    $s20 = "){return \"CTm\";})(),(function fuck(){return \"CTm\";})(),(function fuck(){return \"CTm\";})(),(function fuck(){return \"GJx\";" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}