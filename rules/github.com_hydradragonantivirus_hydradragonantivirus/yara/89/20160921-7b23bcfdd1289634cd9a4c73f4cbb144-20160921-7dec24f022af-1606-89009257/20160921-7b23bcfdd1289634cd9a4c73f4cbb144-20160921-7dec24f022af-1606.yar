rule _20160921_7b23bcfdd1289634cd9a4c73f4cbb144_20160921_7dec24f022af_1606 {
  meta:
    description = "datamaliciousorder - from files 20160921_7b23bcfdd1289634cd9a4c73f4cbb144.js, 20160921_7dec24f022af3c1ffe46748172dd6cad.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7a94fbc46ac51a544406f9a59bf405cd1e19e8e6681d7feacbc81e5ab7d4a50b"
    hash2       = "402e919998fdba69cb3992879db4f947916245c38915db643643952fa450e947"

  strings:
    $s1  = "rn \"YAv\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Oh\";})(),(f" ascii
    $s2  = "t\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MBg\";})(),(function" ascii
    $s3  = "fuck(){return \"Yk\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"IPu" ascii
    $s4  = "n \"Sx\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";})(),(fu" ascii
    $s5  = "fuck(){return \"Sx\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx" ascii
    $s6  = "(function fuck(){return \"IPu\";})(),(function fuck(){return \"Et\";})(),(function fuck(){return \"Et\";})(),(function fuck(){re" ascii
    $s7  = "ck(){return \"IPu\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){return \"SUi\";})(),(function fuck(){return \"UOe" ascii
    $s8  = "ion fuck(){return \"ADy\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"To\";})(),(function fuck(){return " ascii
    $s9  = " fuck(){return \"Jo\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"M" ascii
    $s10 = "rn \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MIl\";})(),(function fuck(){return \"KVh\";})(),(" ascii
    $s11 = "){return \"Zy\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MBg\";})" ascii
    $s12 = ")(),(function fuck(){return \"Jh\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"IPu\";})(),(function fuck(" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}