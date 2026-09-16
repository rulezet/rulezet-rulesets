rule _20160921_0f4dee7115fed314f330d52696c0d1d1_20160921_87978dcbc3a2_302 {
  meta:
    description = "datamaliciousorder - from files 20160921_0f4dee7115fed314f330d52696c0d1d1.js, 20160921_87978dcbc3a23f5dbd5fc73bee04f432.js, 20160921_940fdd83fcdf499d0ebc071f779bd880.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dec7336f5db71057e4227c26b20731cd69ad29c7628e161fff2f7964754477b1"
    hash2       = "a6d96c94cf7f327ade629dec6f41b2fcfa7f7accfa8da780df3fea48273270dd"
    hash3       = "b73c87ed73bc62067299b13aaa227535cbedafa1a7f74ad02273d1aad3a3449f"

  strings:
    $s1  = "eturn \"TTs\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"UOe\";})()," ascii
    $s2  = "\"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"USf\";})(),(fun" ascii
    $s3  = ";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"MOj\";})(),(function fu" ascii
    $s4  = "TTs\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"UOe\";})(),(funct" ascii
    $s5  = ",(function fuck(){return \"LGo\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){" ascii
    $s6  = "ck(){return \"Cd\";})(),(function fuck(){return \"OPz\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Nm\"" ascii
    $s7  = "r\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"TTs\";})(),(functio" ascii
    $s8  = " fuck(){return \"LGo\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"I" ascii
    $s9  = "ion fuck(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return" ascii
    $s10 = "n \"RAi\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"IRn\";})(),(fu" ascii
    $s11 = "ck(){return \"PDf\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"IKv" ascii
    $s12 = "fuck(){return \"Mw\";})(),(function fuck(){return \"UXf\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"YQ" ascii
    $s13 = "(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"Vb\";})(),(function fuck(" ascii
    $s14 = "f\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"USf\";})(),(functio" ascii
    $s15 = "return \"Np\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"UOe\";})()" ascii
    $s16 = "k(){return \"MBg\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){return \"DWe\";})(),(function fuck(){return \"Ve\";" ascii
    $s17 = "ion fuck(){return \"UOe\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return " ascii
    $s18 = "n fuck(){return \"TTs\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"" ascii
    $s19 = "ck(){return \"Vb\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"IRn\"" ascii
    $s20 = "\"OQr\";})(),(function fuck(){return \"Vf\";})(),(function fuck(){return \"XCr\";})(),(function fuck(){return \"AUx\";})(),(func" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}