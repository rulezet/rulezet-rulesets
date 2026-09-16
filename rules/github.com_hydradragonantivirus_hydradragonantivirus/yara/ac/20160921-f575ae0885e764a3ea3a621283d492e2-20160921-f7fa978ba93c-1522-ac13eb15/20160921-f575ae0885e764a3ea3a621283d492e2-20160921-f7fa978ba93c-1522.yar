rule _20160921_f575ae0885e764a3ea3a621283d492e2_20160921_f7fa978ba93c_1522 {
  meta:
    description = "datamaliciousorder - from files 20160921_f575ae0885e764a3ea3a621283d492e2.js, 20160921_f7fa978ba93ca4504da33fc02cbf7f53.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "56a063ba0d781a52d612f976f937d59e64bb8200cf3c4b448f3cb3013733bdaf"
    hash2       = "8c8d20603b0870465254e9f226f52f020b5b1d986c61571e7a3097b32ea728e0"

  strings:
    $s1  = "(){return \"IPu\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"We\";})(),(function fuck(){return \"Za\";})" ascii
    $s2  = "ion fuck(){return \"KVh\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return" ascii
    $s3  = " \"Wo\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"IPu\";})(),(func" ascii
    $s4  = "){return \"AUx\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"Ug\";}" ascii
    $s5  = "Nm\";})(),(function fuck(){return \"GWo\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";})(),(functi" ascii
    $s6  = "rn \"IPu\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"Av\";})(),(fu" ascii
    $s7  = "ck(){return \"Hs\";})(),(function fuck(){return \"GJx\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"USf\"" ascii
    $s8  = "uck(){return \"YQt\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"Wo\";})(),(function fuck(){return \"PDf" ascii
    $s9  = "return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Wo0\";})(),(function fuck(){return \"Zy\";})(" ascii
    $s10 = "Pu\";})(),(function fuck(){return \"Zy\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){return \"KVh\";})(),(functio" ascii
    $s11 = ";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"SUi\";})(),(function fuck(){return \"YQt\";})(),(function fu" ascii
    $s12 = ";})(),(function fuck(){return \"YAv\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"IPu\";})(),(function f" ascii
    $s13 = "k(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"Ai\";" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}