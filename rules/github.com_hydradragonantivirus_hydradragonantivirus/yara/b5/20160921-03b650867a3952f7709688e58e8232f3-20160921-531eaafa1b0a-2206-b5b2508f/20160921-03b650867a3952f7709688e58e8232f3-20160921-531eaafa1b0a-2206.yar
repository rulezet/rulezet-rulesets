rule _20160921_03b650867a3952f7709688e58e8232f3_20160921_531eaafa1b0a_2206 {
  meta:
    description = "datamaliciousorder - from files 20160921_03b650867a3952f7709688e58e8232f3.js, 20160921_531eaafa1b0a00d86f2203fbd289dd63.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a775853212fe6663d7c077a64c0d4c851d4b7f261a6c0846b4552b556e12a5fe"
    hash2       = "d28500022264ce61d9d988db6f8ddee46acc7dea6f898510f532ee48f87a0c93"

  strings:
    $s1 = "MBg\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Vf\";})(),(function fuck(){return \"We\";})(),(functio" ascii
    $s2 = "function fuck(){return \"CCb\";})(),(function fuck(){return \"Jh\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){re" ascii
    $s3 = "b\";})(),(function fuck(){return \"Jh\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"Ug\";})(),(function " ascii
    $s4 = "ck(){return \"RAi\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"GNm" ascii
    $s5 = "(),(function fuck(){return \"Wo\";})(),(function fuck(){return \"Wo0\";})(),(function fuck(){return \"NKq\";})(),(function fuck(" ascii
    $s6 = "uck(){return \"Ug\";})(),(function fuck(){return \"ZLd\";})(),(function fuck(){return \"IOs\";})(),(function fuck(){return \"RAi" ascii
    $s7 = "){return \"Dc\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"Pc\";})(),(function fuck(){return \"ZWu\";})(" ascii
    $s8 = " \"Zy\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return \"MOj\";})(),(funct" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}