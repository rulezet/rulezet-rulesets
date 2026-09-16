rule _20160921_232b12ddd1b901389868a9b4ede90a00_20160921_a10895ba237c_33 {
  meta:
    description = "datamaliciousorder - from files 20160921_232b12ddd1b901389868a9b4ede90a00.js, 20160921_a10895ba237c1e6f37301bc7a7a20160.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6982702aaaeaeac05c8666dd848834fd26e9eba567a0d41d04253252c120cdfe"
    hash2       = "a07dda373b4221628323bb92f53033ef3290be02ec657056fbf01d7d1efe96d7"

  strings:
    $s1  = "on fuck(){return \"IPu\";})(),(function fuck(){return \"Zy\";})(),(function fuck(){return \"GWo\";})(),(function fuck(){return " ascii
    $s2  = "b\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"IRn\";})(),(function" ascii
    $s3  = "){return \"Cd\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"USf\";}" ascii
    $s4  = "rn \"MIl\";})(),(function fuck(){return \"KVh\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"IPu\";})(),(f" ascii
    $s5  = " \"Vb\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"NKq\";})(),(func" ascii
    $s6  = "on fuck(){return \"USf\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return " ascii
    $s7  = "n fuck(){return \"IPu\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return " ascii
    $s8  = "return \"ADy\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"UOe\";})(" ascii
    $s9  = "unction fuck(){return \"Na\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){ret" ascii
    $s10 = "n \"Nm\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"OQr\";})(),(fu" ascii
    $s11 = " fuck(){return \"Cd\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){return \"S" ascii
    $s12 = "d\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"Ug\";})(),(function" ascii
    $s13 = "rn \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Oh\";})(),(function fuck(){return \"Oh\";})(),(fu" ascii
    $s14 = "rn \"IPu\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"LGo\";})(),(f" ascii
    $s15 = " \"TTs\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"USf\";})(),(func" ascii
    $s16 = " fuck(){return \"Np\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"NK" ascii
    $s17 = "rn \"Np\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"IPu\";})(),(fu" ascii
    $s18 = "k(){return \"CTm\";})(),(function fuck(){return \"CTm\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"ZWu\"" ascii
    $s19 = "n \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"Sx\";})(),(fun" ascii
    $s20 = ",(function fuck(){return \"DRx\";})(),(function fuck(){return \"We\";})(),(function fuck(){return \"QTc\";})(),(function fuck(){" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}