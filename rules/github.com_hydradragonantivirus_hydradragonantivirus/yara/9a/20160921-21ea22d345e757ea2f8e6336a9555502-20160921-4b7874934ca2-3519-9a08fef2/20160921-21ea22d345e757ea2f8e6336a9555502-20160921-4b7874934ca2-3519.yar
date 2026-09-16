rule _20160921_21ea22d345e757ea2f8e6336a9555502_20160921_4b7874934ca2_3519 {
  meta:
    description = "datamaliciousorder - from files 20160921_21ea22d345e757ea2f8e6336a9555502.js, 20160921_4b7874934ca20c6643210a0c92fe260f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e8743d09e1e870afab5e1ecd8d21f82873a9da6a025b74f14bc65477cea8f023"
    hash2       = "858cb8ac4dab1ec1e6a2a0bb435765157525269e75820991212eee18a2d91717"

  strings:
    $s1 = "\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"DWe\";})(),(function fuck(){return \"IPu\";})(),(function " ascii
    $s2 = "n \"ADy\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"AUx\";})(),(fu" ascii
    $s3 = "),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){" ascii
    $s4 = "ck(){return \"UOe\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"Ug" ascii
    $s5 = "unction fuck(){return \"Vb\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){ret" ascii
    $s6 = "k(){return \"LGo\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"IRn" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}