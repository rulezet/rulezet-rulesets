rule _20160921_a210d5e93bf8b06dbd0a1b262abe210f_20160921_abc9044816c2_1515 {
  meta:
    description = "datamaliciousorder - from files 20160921_a210d5e93bf8b06dbd0a1b262abe210f.js, 20160921_abc9044816c2455dc24ac338746b6bd5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "681408ae198939a760d376554e62f86e9d1fe2306266ffaee496dc9eed4d0687"
    hash2       = "2bb53920235afb1c2d16f013bc118d1df64065eefc10c1b2b9e7a4b133850850"

  strings:
    $s1  = "turn \"Bz\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"Bz\";})()];" fullword ascii
    $s2  = "eturn \"UXf\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"UXf\";})()" ascii
    $s3  = "return \"CTm\";})(),(function fuck(){return \"CTm\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"DWe\";})(" ascii
    $s4  = ",(function fuck(){return \"YQt\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){return \"Wo0\";})(),(function fuck()" ascii
    $s5  = "Sf\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"DWe\";})(),(function fuck(){return \"Dc\";})(),(functio" ascii
    $s6  = "MOj\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"Bz\";})(),(functi" ascii
    $s7  = " \"Xw\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"NKq\";})(),(func" ascii
    $s8  = "rn \"Xg\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"Bz\";})(),(fu" ascii
    $s9  = "uck(){return \"Ve\";})(),(function fuck(){return \"CCb\";})(),(function fuck(){return \"EHo\";})(),(function fuck(){return \"IPu" ascii
    $s10 = "on fuck(){return \"GNm\";})(),(function fuck(){return \"Bz\";})(),(function fuck(){return \"CTm\";})(),(function fuck(){return " ascii
    $s11 = "\"Zy\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"IRn\";})(),(functi" ascii
    $s12 = "{return \"LGo\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"IRn\";})(" ascii
    $s13 = "fuck(){return \"TTs\";})(),(function fuck(){return \"Yk\";})(),(function fuck(){return \"GJx\";})(),(function fuck(){return \"ZV" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}