rule _20160921_67612c4ac75c1d3511dd9358b66e9fc5_20160921_de03e8e8d98d_3019 {
  meta:
    description = "datamaliciousorder - from files 20160921_67612c4ac75c1d3511dd9358b66e9fc5.js, 20160921_de03e8e8d98da4b7d17147c979ce9ff8.js, 20160921_fa89d54bd5a7a27defe09d5a56b5a881.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fbf6986e3a8c7defa5c14d80cff4f3b3ce1db859ea94044f5d024758684178c0"
    hash2       = "aa4eb617dd497a7ea1d016d98ce4ca8e81e13b4e240c42d46d01e84e617a150b"
    hash3       = "30f2a7c2562ef79254c8129be50246b9c41eb24f000c8cfbd0f4f8c28b49b00f"

  strings:
    $s1 = " \"OQr\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"Za\";})(),(func" ascii
    $s2 = "k(){return \"Ml\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"RAi\"" ascii
    $s3 = " fuck(){return \"Dc\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"Pc\";})(),(function fuck(){return \"IO" ascii
    $s4 = "ion fuck(){return \"RAi\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return " ascii
    $s5 = "k(){return \"Dc\";})(),(function fuck(){return \"UXf\";})(),(function fuck(){return \"DAa\";})(),(function fuck(){return \"TTs\"" ascii
    $s6 = ",(function fuck(){return \"EHo\";})(),(function fuck(){return \"Ar\";})(),(function fuck(){return \"QTc\";})(),(function fuck(){" ascii
    $s7 = ",(function fuck(){return \"LGo\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}