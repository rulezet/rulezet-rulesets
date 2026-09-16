rule _20160921_214342143d6b7e971a1c8d2679379cb7_20160921_6a795b298894_3510 {
  meta:
    description = "datamaliciousorder - from files 20160921_214342143d6b7e971a1c8d2679379cb7.js, 20160921_6a795b29889480550a8440815b06fa7d.js, 20160921_e6b8063519cd61bbba9375bf86215501.js, 20160921_fa89d54bd5a7a27defe09d5a56b5a881.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8dcc208c118a95c2f88df14e844ed832ee1e06bdf992329e8a721bd7aaa936e8"
    hash2       = "fb5890246703edf23742bd2e821c50d1610d87dc3d17ff4909414fae3bd26d96"
    hash3       = "70ad2f9c8f844d4c80b1d4ce0f71f62f74e64671ae11d2d3af8e6ec764993403"
    hash4       = "30f2a7c2562ef79254c8129be50246b9c41eb24f000c8cfbd0f4f8c28b49b00f"

  strings:
    $s1 = "ck(){return \"QTc\";})(),(function fuck(){return \"Mw\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"Fv\";" ascii
    $s2 = "\"Ve\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"Ug\";})(),(functio" ascii
    $s3 = "urn \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"MUs\";})(),(f" ascii
    $s4 = " fuck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"Wo" ascii
    $s5 = "nction fuck(){return \"XFd\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){retur" ascii
    $s6 = "n \"Nm\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return \"Pc\";})(),(function fuck(){return \"XHj\";})(),(fun" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}