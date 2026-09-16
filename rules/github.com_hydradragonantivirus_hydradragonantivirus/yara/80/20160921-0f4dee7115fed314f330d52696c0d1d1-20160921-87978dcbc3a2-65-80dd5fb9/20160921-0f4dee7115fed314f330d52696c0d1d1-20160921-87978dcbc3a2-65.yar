rule _20160921_0f4dee7115fed314f330d52696c0d1d1_20160921_87978dcbc3a2_65 {
  meta:
    description = "datamaliciousorder - from files 20160921_0f4dee7115fed314f330d52696c0d1d1.js, 20160921_87978dcbc3a23f5dbd5fc73bee04f432.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dec7336f5db71057e4227c26b20731cd69ad29c7628e161fff2f7964754477b1"
    hash2       = "a6d96c94cf7f327ade629dec6f41b2fcfa7f7accfa8da780df3fea48273270dd"

  strings:
    $s1  = "),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"Na\";})(),(function fuck(){" ascii
    $s2  = "ck(){return \"GNm\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"Ug\"" ascii
    $s3  = "unction fuck(){return \"PDf\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){ret" ascii
    $s4  = "(function fuck(){return \"Jo\";})(),(function fuck(){return \"MIl\";})(),(function fuck(){return \"FJs\";})(),(function fuck(){r" ascii
    $s5  = "ction fuck(){return \"Et\";})(),(function fuck(){return \"Na\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return" ascii
    $s6  = "nction fuck(){return \"ADy\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){ret" ascii
    $s7  = "o\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"NKq\";})(),(functio" ascii
    $s8  = "IOs\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"YQt\";})(),(funct" ascii
    $s9  = ";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"IPu\";})(),(function f" ascii
    $s10 = "eturn \"Vb\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"Vb\";})()," ascii
    $s11 = "\"Xg\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ug\";})(),(function fuck(){return \"Bz\";})(),(functi" ascii
    $s12 = "unction fuck(){return \"LGo\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"USf\";})(),(function fuck(){ret" ascii
    $s13 = "MBg\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Yk\";})(),(function fuck(){return \"MUs\";})(),(functi" ascii
    $s14 = "uck(){return \"XCr\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"DRx" ascii
    $s15 = "ck(){return \"IPu\";})(),(function fuck(){return \"Et\";})(),(function fuck(){return \"GJx\";})(),(function fuck(){return \"YAv" ascii
    $s16 = " \"QTc\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"OQr\";})(),(fu" ascii
    $s17 = "\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"Av\";})(),(function fuck(){return \"USf\";})(),(function f" ascii
    $s18 = "){return \"Cd\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"MBg\";}" ascii
    $s19 = "\"IPu\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"FJs\";})(),(function fuck(){return \"Xw\";})(),(funct" ascii
    $s20 = "uck(){return \"LGo\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"IP" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}