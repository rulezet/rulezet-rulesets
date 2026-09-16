rule _20160921_1d5a5ba6420732e8f626755a81334ad4_20160921_5143fd2835d0_1547 {
  meta:
    description = "datamaliciousorder - from files 20160921_1d5a5ba6420732e8f626755a81334ad4.js, 20160921_5143fd2835d058f3854ef7b166166de4.js, 20160921_694d4629e99fd1d23d60bc73e0e28e30.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "47a1fbd3f8785b259468283f9d6611b34da6b0170d66a933ade09c56548f89b4"
    hash2       = "0824c6197846b6efc3bea2626d4bc5983302ec11dd40189770e6572811d3d42c"
    hash3       = "01147c2f2f43df58f5a1b60481a04add7d73eba030abaeed3f9dedb1fd3574e4"

  strings:
    $s1  = "\"To\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"IPu\";})(),(func" ascii
    $s2  = "uck(){return \"IPu\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"EHo\";})(),(function fuck(){return \"Np" ascii
    $s3  = "rn \"GWo\";})(),(function fuck(){return \"DAa\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"IPu\";})(),(f" ascii
    $s4  = ",(function fuck(){return \"ADy\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){" ascii
    $s5  = "on fuck(){return \"XCr\";})(),(function fuck(){return \"YAv\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return " ascii
    $s6  = "unction fuck(){return \"Np\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){ret" ascii
    $s7  = "(function fuck(){return \"Np\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){r" ascii
    $s8  = "k(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"AUx\"" ascii
    $s9  = "n \"We\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";})(),(fu" ascii
    $s10 = "uck(){return \"IPu\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"QTc" ascii
    $s11 = " \"GWo\";})(),(function fuck(){return \"EHo\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";})(),(fu" ascii
    $s12 = " fuck(){return \"MBg\";})(),(function fuck(){return \"Wo\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"YA" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}