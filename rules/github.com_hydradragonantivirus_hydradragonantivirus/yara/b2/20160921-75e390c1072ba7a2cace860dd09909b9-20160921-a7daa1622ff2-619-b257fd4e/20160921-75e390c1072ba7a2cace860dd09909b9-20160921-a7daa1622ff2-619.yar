rule _20160921_75e390c1072ba7a2cace860dd09909b9_20160921_a7daa1622ff2_619 {
  meta:
    description = "datamaliciousorder - from files 20160921_75e390c1072ba7a2cace860dd09909b9.js, 20160921_a7daa1622ff2bc3dccfc20f622902f7b.js, 20160921_bf6b3f12d2bf727319a9cd8aa9a170cc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0de804f026f55adb786d09f07b7f96808213c0d0809b41d659332d25a2645536"
    hash2       = "4caa07134c114c6f14592ae1a6f87a08bd21b6048c96d44b5eb70d9762008059"
    hash3       = "6ff891fcf6c12c36bf13bc65b82adbb923eb443ffdabd587f48e44c93323b786"

  strings:
    $s1  = "fuck(){return \"Dc\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx" ascii
    $s2  = " fuck(){return \"XFd\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"M" ascii
    $s3  = "nction fuck(){return \"Yk\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"Za\";})(),(function fuck(){retur" ascii
    $s4  = "\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"XCr\";})(),(function " ascii
    $s5  = "Tc\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MBg\";})(),(functio" ascii
    $s6  = "tion fuck(){return \"IPu\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){return \"SUi\";})(),(function fuck(){retur" ascii
    $s7  = " fuck(){return \"SUi\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"M" ascii
    $s8  = "uck(){return \"IPu\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"Ug\";})(),(function fuck(){return \"Ik\"" ascii
    $s9  = "k(){return \"IPu\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"MUs\";" ascii
    $s10 = "return \"Py\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"RAi\";})()" ascii
    $s11 = "turn \"Jo\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"IPu\";})(),(" ascii
    $s12 = "})(),(function fuck(){return \"Oh\";})(),(function fuck(){return \"Ug\";})(),(function fuck(){return \"KVh\";})(),(function fuck" ascii
    $s13 = "turn \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Oh\";})(),(function fuck(){return \"Ug\";})(),(" ascii
    $s14 = "ck(){return \"Sx\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"Wo\";" ascii
    $s15 = "(){return \"YQt\";})(),(function fuck(){return \"QTc\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\"" ascii
    $s16 = "ion fuck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"We\";})(),(function fuck(){return " ascii
    $s17 = "rn \"IPu\";})(),(function fuck(){return \"CCb\";})(),(function fuck(){return \"Ug\";})(),(function fuck(){return \"UXf\";})(),(f" ascii
    $s18 = "fuck(){return \"Jo\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){return \"UXf" ascii
    $s19 = "u\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){return \"Na\";})(),(function " ascii
    $s20 = "urn \"YQt\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MBg\";})(),(" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}