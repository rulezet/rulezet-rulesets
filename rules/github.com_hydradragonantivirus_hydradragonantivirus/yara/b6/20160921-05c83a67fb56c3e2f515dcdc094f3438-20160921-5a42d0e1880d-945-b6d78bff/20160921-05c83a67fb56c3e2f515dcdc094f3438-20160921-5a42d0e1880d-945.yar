rule _20160921_05c83a67fb56c3e2f515dcdc094f3438_20160921_5a42d0e1880d_945 {
  meta:
    description = "datamaliciousorder - from files 20160921_05c83a67fb56c3e2f515dcdc094f3438.js, 20160921_5a42d0e1880d178346694a30bc112076.js, 20160921_8b9d3c425718975422f8fe0d71119686.js, 20160921_a2f8f3f44ef6a3341feac8fb57e829ce.js, 20160921_b714100d69b955de920a302ff8bef7db.js, 20160921_c4afaa1e41efa7633248f1941bda4010.js, 20160921_dc73cfa7a33eb762f38614c69a95919d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0535a055f646391a67e495ab3466f375b47d00382cf1ac28c70355309533f19c"
    hash2       = "ca8e81eec437e87b27dedb202751f13e736aa092e78fffde5fbf40616f2e3738"
    hash3       = "523032dc97c061d21e22a215d1568aa470cd8d5f46ddb3bae63dafcde8db3687"
    hash4       = "619e82812300e58dd7cd06b8fbcf2f7e3f6757812cc075603c82363ab6481758"
    hash5       = "fc43d54db3c24d6f7ce2d47a45ffcd0768d5cfe90e405322e477be98fe4a8170"
    hash6       = "64cdab0c251929ea414823662957bad76268a8398b0c708715609f37e7070a69"
    hash7       = "50e80269adbbca38f500219eaf7cec16f396b3d8a7c56d342b2e4839819ea598"

  strings:
    $s1  = "function fuck(){return \"Xw\";})(),(function fuck(){return \"Pc\";})(),(function fuck(){return \"KVh\";})(),(function fuck(){ret" ascii
    $s2  = "nction fuck(){return \"IPu\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){retu" ascii
    $s3  = "urn \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Et\";})(),(function fuck(){return \"CCb\";})(),(f" ascii
    $s4  = "turn \"Na\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MBg\";})()," ascii
    $s5  = "\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"UXf\";})(),(function" ascii
    $s6  = ";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Yk\";})(),(function fuck(){return \"Ve\";})(),(function fuc" ascii
    $s7  = "uck(){return \"IPu\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){return \"To" ascii
    $s8  = "turn \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Wo\";})(),(function fuck(){return \"Nm\";})(),(f" ascii
    $s9  = "on fuck(){return \"We\";})(),(function fuck(){return \"FJs\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return " ascii
    $s10 = "\"IPu\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){return \"Jg\";})(),(funct" ascii
    $s11 = "(){return \"MIl\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MBg\";" ascii
    $s12 = "uck(){return \"IPu\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"EHo" ascii
    $s13 = "function fuck(){return \"XCr\";})(),(function fuck(){return \"GJx\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){r" ascii
    $s14 = "fuck(){return \"Dc\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MBg" ascii
    $s15 = "),(function fuck(){return \"Xw\";})(),(function fuck(){return \"VMi\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){" ascii
    $s16 = "nction fuck(){return \"IPu\";})(),(function fuck(){return \"We\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){retu" ascii
    $s17 = "){return \"Xw\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"Xw\";})()" ascii
    $s18 = "GJx\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"ZLd\";})(),(functio" ascii
    $s19 = "x\";})(),(function fuck(){return \"ZLd\";})(),(function fuck(){return \"CCb\";})(),(function fuck(){return \"To\";})(),(function" ascii
    $s20 = "(function fuck(){return \"IPu\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"To\";})(),(function fuck(){re" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}