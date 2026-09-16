rule _20160921_4b7874934ca20c6643210a0c92fe260f_20160921_5f14ae6f169c_1716 {
  meta:
    description = "datamaliciousorder - from files 20160921_4b7874934ca20c6643210a0c92fe260f.js, 20160921_5f14ae6f169c53d6d49523d1e13e4ab9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "858cb8ac4dab1ec1e6a2a0bb435765157525269e75820991212eee18a2d91717"
    hash2       = "270eb53363684986d2aef11b6b5bb4cd5c5cb316f626e41b627db2cf899b440e"

  strings:
    $s1  = "on fuck(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return " ascii
    $s2  = "rn \"IPu\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"DAa\";})(),(function fuck(){return \"GNm\";})(),(f" ascii
    $s3  = "eturn \"ZWu\";})(),(function fuck(){return \"MIl\";})(),(function fuck(){return \"Jh\";})(),(function fuck(){return \"IPu\";})()" ascii
    $s4  = "Ai\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"MBg\";})(),(functi" ascii
    $s5  = "})(),(function fuck(){return \"XHj\";})(),(function fuck(){return \"GWo\";})(),(function fuck(){return \"DRx\";})(),(function fu" ascii
    $s6  = "ction fuck(){return \"Ot\";})(),(function fuck(){return \"Na\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return" ascii
    $s7  = "n fuck(){return \"Vb\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"" ascii
    $s8  = ";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"YQt\";})(),(function f" ascii
    $s9  = "t\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"Ug\";})(),(function" ascii
    $s10 = "k(){return \"Vf\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"Et\";}" ascii
    $s11 = "\"UOe\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"Oh\";})(),(func" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}