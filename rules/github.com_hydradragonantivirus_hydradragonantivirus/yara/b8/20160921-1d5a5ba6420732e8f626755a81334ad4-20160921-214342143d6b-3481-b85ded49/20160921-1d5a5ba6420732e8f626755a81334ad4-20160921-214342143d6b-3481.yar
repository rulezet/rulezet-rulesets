rule _20160921_1d5a5ba6420732e8f626755a81334ad4_20160921_214342143d6b_3481 {
  meta:
    description = "datamaliciousorder - from files 20160921_1d5a5ba6420732e8f626755a81334ad4.js, 20160921_214342143d6b7e971a1c8d2679379cb7.js, 20160921_5143fd2835d058f3854ef7b166166de4.js, 20160921_5e30fe0c691277f3c6d0814d796ba918.js, 20160921_e6b8063519cd61bbba9375bf86215501.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "47a1fbd3f8785b259468283f9d6611b34da6b0170d66a933ade09c56548f89b4"
    hash2       = "8dcc208c118a95c2f88df14e844ed832ee1e06bdf992329e8a721bd7aaa936e8"
    hash3       = "0824c6197846b6efc3bea2626d4bc5983302ec11dd40189770e6572811d3d42c"
    hash4       = "7cac2594d8c0286d3110fd3705816d41052df49790da39881cedd79b8cb5c6ed"
    hash5       = "70ad2f9c8f844d4c80b1d4ce0f71f62f74e64671ae11d2d3af8e6ec764993403"

  strings:
    $s1 = "unction fuck(){return \"ZLd\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){ret" ascii
    $s2 = "MOj\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Oh\";})(),(function fuck(){return \"XHj\";})(),(functi" ascii
    $s3 = "ck(){return \"Xg\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"Vf\"" ascii
    $s4 = "eturn \"KVh\";})(),(function fuck(){return \"Jg\";})(),(function fuck(){return \"Ar\";})(),(function fuck(){return \"Fv\";})(),(" ascii
    $s5 = " fuck(){return \"Ik\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"IPu" ascii
    $s6 = "c\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"Ik\";})(),(function f" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}