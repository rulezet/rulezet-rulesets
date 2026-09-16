rule _20160921_4fa304d7c11deb5fb9cd6514d5a983de_20160921_a7daa1622ff2_2077 {
  meta:
    description = "datamaliciousorder - from files 20160921_4fa304d7c11deb5fb9cd6514d5a983de.js, 20160921_a7daa1622ff2bc3dccfc20f622902f7b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cef5a1e67f57d9f24065ff0145644e0185df6abc29113310c6782b30e0a9236b"
    hash2       = "4caa07134c114c6f14592ae1a6f87a08bd21b6048c96d44b5eb70d9762008059"

  strings:
    $s1 = "k(){return \"Ug\";})(),(function fuck(){return \"SUi\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"Wo\";" ascii
    $s2 = "(),(function fuck(){return \"XFd\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"OPz\";})(),(function fuck" ascii
    $s3 = "\";})(),(function fuck(){return \"Jh\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"DRx\";})(),(function " ascii
    $s4 = "nction fuck(){return \"UXf\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){retu" ascii
    $s5 = "),(function fuck(){return \"DRx\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"Et\";})(),(function fuck()" ascii
    $s6 = "urn \"IPu\";})(),(function fuck(){return \"ZLd\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return \"IPu\";})(),(" ascii
    $s7 = "),(function fuck(){return \"RAi\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"Ug\";})(),(function fuck()" ascii
    $s8 = " fuck(){return \"DRx\";})(),(function fuck(){return \"XCr\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"K" ascii
    $s9 = " fuck(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"To\";})(),(function fuck(){return \"M" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}