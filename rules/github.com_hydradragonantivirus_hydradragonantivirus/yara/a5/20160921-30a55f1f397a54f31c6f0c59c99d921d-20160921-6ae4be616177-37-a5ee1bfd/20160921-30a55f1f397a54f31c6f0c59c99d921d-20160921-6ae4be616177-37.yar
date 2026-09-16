rule _20160921_30a55f1f397a54f31c6f0c59c99d921d_20160921_6ae4be616177_37 {
  meta:
    description = "datamaliciousorder - from files 20160921_30a55f1f397a54f31c6f0c59c99d921d.js, 20160921_6ae4be616177cbd93c9c15ffb5dcddae.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1a24b75a2a7e52cbe65ddc3ad587a945b24afb617cb2d98581f0b06c49777984"
    hash2       = "4a4141c2adab0ebca262f25d7f6a45b773b074628a9522401e8dfa28d4889ccb"

  strings:
    $s1  = "\"ADy\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"IPu\";})(),(funct" ascii
    $s2  = "uck(){return \"IPu\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"USf" ascii
    $s3  = "return \"Cd\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"PDf\";})(" ascii
    $s4  = "ction fuck(){return \"Yb\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return" ascii
    $s5  = "\"IPu\";})(),(function fuck(){return \"ZLd\";})(),(function fuck(){return \"Jg\";})(),(function fuck(){return \"GNm\";})(),(func" ascii
    $s6  = "n \"TTs\";})(),(function fuck(){return \"GWo\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return \"IPu\";})(),(fu" ascii
    $s7  = ",(function fuck(){return \"Pc\";})(),(function fuck(){return \"FJs\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){r" ascii
    $s8  = "on fuck(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return " ascii
    $s9  = ")(),(function fuck(){return \"Oh\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"IPu\";})(),(function fuck(" ascii
    $s10 = "rn \"TTs\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"Vb\";})(),(f" ascii
    $s11 = "nction fuck(){return \"USf\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){ret" ascii
    $s12 = "\"TTs\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"Cd\";})(),(func" ascii
    $s13 = "u\";})(),(function fuck(){return \"Yk\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"IPu\";})(),(function " ascii
    $s14 = " \"TTs\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"IPu\";})(),(fu" ascii
    $s15 = "n \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Oh\";})(),(function fuck(){return \"Oh\";})(),(fun" ascii
    $s16 = " fuck(){return \"Np\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"GN" ascii
    $s17 = "n fuck(){return \"OPz\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"ZLd\";})(),(function fuck(){return " ascii
    $s18 = "m\";})(),(function fuck(){return \"CTm\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"YAv\";})(),(functio" ascii
    $s19 = "){return \"Cd\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"IRn\";}" ascii
    $s20 = "ck(){return \"GWo\";})(),(function fuck(){return \"EHo\";})(),(function fuck(){return \"Pc\";})(),(function fuck(){return \"Ar\"" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}