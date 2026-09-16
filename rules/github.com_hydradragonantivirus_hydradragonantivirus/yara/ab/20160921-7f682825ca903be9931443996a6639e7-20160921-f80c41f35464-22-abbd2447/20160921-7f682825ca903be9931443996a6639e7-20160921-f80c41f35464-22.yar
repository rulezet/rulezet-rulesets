rule _20160921_7f682825ca903be9931443996a6639e7_20160921_f80c41f35464_22 {
  meta:
    description = "datamaliciousorder - from files 20160921_7f682825ca903be9931443996a6639e7.js, 20160921_f80c41f35464b4c1cc71c3a8431a6e96.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0702db471409264d1d764fadd3401cdedc4b3ca7166d99d61893fad5007d7f03"
    hash2       = "8186d069d8ec2c8754bba46343500f71eff6d1d47a5ecb2ca82a097bf5b41dc3"

  strings:
    $s1  = "nction fuck(){return \"Xw\";})(),(function fuck(){return \"Jg\";})(),(function fuck(){return \"Pc\";})(),(function fuck(){return" ascii
    $s2  = "x\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){return \"PDf\";})(),(function" ascii
    $s3  = " fuck(){return \"XFd\";})(),(function fuck(){return \"KVh\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"" ascii
    $s4  = "urn \"AUx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Cs\";})(),(function fuck(){return \"IPu\";})(),(" ascii
    $s5  = "ion fuck(){return \"SUi\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return" ascii
    $s6  = "\";})(),(function fuck(){return \"GJx\";})(),(function fuck(){return \"IOs\";})(),(function fuck(){return \"AUx\";})(),(function" ascii
    $s7  = "turn \"CCb\";})(),(function fuck(){return \"Mw\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"IPu\";})()," ascii
    $s8  = " fuck(){return \"IPu\";})(),(function fuck(){return \"ZLd\";})(),(function fuck(){return \"Wo0\";})(),(function fuck(){return \"" ascii
    $s9  = "(){return \"Dc\";})(),(function fuck(){return \"ZVi\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"Cd\";})" ascii
    $s10 = "ion fuck(){return \"YQt\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return" ascii
    $s11 = "{return \"Fv\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return \"YAv\";})(" ascii
    $s12 = "fuck(){return \"Qh\";})(),(function fuck(){return \"To\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return \"RAi" ascii
    $s13 = "){return \"TTs\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"YQt\";}" ascii
    $s14 = "unction fuck(){return \"Ve\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"Ar\";})(),(function fuck(){retu" ascii
    $s15 = "fuck(){return \"AUx\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"Y" ascii
    $s16 = "return \"RAi\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"IRn\";})" ascii
    $s17 = "urn \"YQt\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"IRn\";})()," ascii
    $s18 = "(function fuck(){return \"ZLd\";})(),(function fuck(){return \"Na\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){r" ascii
    $s19 = "function fuck(){return \"Ar\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"OPz\";})(),(function fuck(){re" ascii
    $s20 = "nction fuck(){return \"USf\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){ret" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}