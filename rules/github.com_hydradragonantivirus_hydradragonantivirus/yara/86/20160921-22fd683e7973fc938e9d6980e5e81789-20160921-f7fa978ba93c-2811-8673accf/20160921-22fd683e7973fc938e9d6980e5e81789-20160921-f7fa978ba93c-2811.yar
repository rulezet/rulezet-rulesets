rule _20160921_22fd683e7973fc938e9d6980e5e81789_20160921_f7fa978ba93c_2811 {
  meta:
    description = "datamaliciousorder - from files 20160921_22fd683e7973fc938e9d6980e5e81789.js, 20160921_f7fa978ba93ca4504da33fc02cbf7f53.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c3583ada9b0a35137add948ee4bd3182a5f977a0dbcc3a39c01ee288f703d566"
    hash2       = "8c8d20603b0870465254e9f226f52f020b5b1d986c61571e7a3097b32ea728e0"

  strings:
    $s1 = "ction fuck(){return \"IPu\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){retu" ascii
    $s2 = " fuck(){return \"IPu\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"Pc\";})(),(function fuck(){return \"GN" ascii
    $s3 = "turn \"OQr\";})(),(function fuck(){return \"Ar\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"GNm\";})()," ascii
    $s4 = "(){return \"Ug\";})(),(function fuck(){return \"Bz\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"YAv\";})" ascii
    $s5 = "),(function fuck(){return \"GNm\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"LGo\";})(),(function fuck(" ascii
    $s6 = "rn \"USf\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"LLv\";})(),(" ascii
    $s7 = "(){return \"Bz\";})(),(function fuck(){return \"CTm\";})(),(function fuck(){return \"CTm\";})(),(function fuck(){return \"Ug\";}" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}