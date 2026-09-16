rule _20160921_3a2902eaca0b2b91120958418b46c844_20160921_ae190d4c26ff_1342 {
  meta:
    description = "datamaliciousorder - from files 20160921_3a2902eaca0b2b91120958418b46c844.js, 20160921_ae190d4c26ff954cee57fde04839fdcd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "063bab1922376d926db97bdcd4342c2e9b0f2ec98d9fad81c2a3f86537c82b07"
    hash2       = "0a337ab3ebbd0c762482045ac2f2536c27fbe1276893efdedbafc2c805709064"

  strings:
    $s1  = "Et\";})(),(function fuck(){return \"IOs\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MBg\";})(),(functi" ascii
    $s2  = ")(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"GJx\";})(),(function fuck(){return \"Za\";})(),(function fuck(" ascii
    $s3  = "),(function fuck(){return \"GJx\";})(),(function fuck(){return \"Et\";})(),(function fuck(){return \"MUs\";})(),(function fuck()" ascii
    $s4  = " \"Xw\";})(),(function fuck(){return \"FJs\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"Dc\";})(),(funct" ascii
    $s5  = "ck(){return \"IPu\";})(),(function fuck(){return \"GJx\";})(),(function fuck(){return \"SUi\";})(),(function fuck(){return \"USf" ascii
    $s6  = "n \"Xw\";})(),(function fuck(){return \"Oh\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){return \"Xw\";})(),(func" ascii
    $s7  = "tion fuck(){return \"IRn\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){retur" ascii
    $s8  = "return \"Jo\";})(),(function fuck(){return \"FJs\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MBg\";})(" ascii
    $s9  = "(){return \"IOs\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"IPu\";}" ascii
    $s10 = "urn \"Ik\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"Xw\";})(),(fun" ascii
    $s11 = "ion fuck(){return \"Ai\";})(),(function fuck(){return \"FJs\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return " ascii
    $s12 = "a\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"GJx\";})(),(function fuck(){return \"YAv\";})(),(functio" ascii
    $s13 = "return \"IPu\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"QTc\";})()" ascii
    $s14 = "unction fuck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){ret" ascii
    $s15 = "ion fuck(){return \"IPu\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"Vf\";})(),(function fuck(){return " ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}