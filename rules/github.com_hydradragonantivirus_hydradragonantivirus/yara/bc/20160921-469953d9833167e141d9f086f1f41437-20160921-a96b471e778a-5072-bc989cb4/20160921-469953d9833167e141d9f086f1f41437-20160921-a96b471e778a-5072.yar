rule _20160921_469953d9833167e141d9f086f1f41437_20160921_a96b471e778a_5072 {
  meta:
    description = "datamaliciousorder - from files 20160921_469953d9833167e141d9f086f1f41437.js, 20160921_a96b471e778a8101c168e06727d930fb.js, 20160921_ccb7f2594ec30d819d8973993796faf6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e29808d818b8f5ea60d0baa8d6c3284d3673878f7f4309c5981ced86dc40c5f1"
    hash2       = "f39378ed9c109b442c660bd7c383f0420860e3ac084eca6bb2fd789ead573a49"
    hash3       = "d05110dd6f0ccc6122f08dac231858be0e233eb3cfb596f5f571556d227ab3ef"

  strings:
    $s1 = "uck(){return \"Sx\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"Pc\";})(),(function fuck(){return \"Za\"" ascii
    $s2 = "\";})(),(function fuck(){return \"Ar\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"Ik\";})(),(function fu" ascii
    $s3 = "unction fuck(){return \"Xg\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return \"KVh\";})(),(function fuck(){retu" ascii
    $s4 = "n \"IPu\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"Vf\";})(),(function fuck(){return \"ZLd\";})(),(fu" ascii
    $s5 = "turn \"Fv\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Yb\";})(),(f" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}