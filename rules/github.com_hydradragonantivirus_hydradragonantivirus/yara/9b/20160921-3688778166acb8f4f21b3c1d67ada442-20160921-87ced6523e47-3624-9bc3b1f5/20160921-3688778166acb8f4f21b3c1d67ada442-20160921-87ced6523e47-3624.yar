rule _20160921_3688778166acb8f4f21b3c1d67ada442_20160921_87ced6523e47_3624 {
  meta:
    description = "datamaliciousorder - from files 20160921_3688778166acb8f4f21b3c1d67ada442.js, 20160921_87ced6523e47b3b752b2353107bc989a.js, 20160921_945a46518061bd8e157aed251e0ffa9e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "03559b6095f398f17a62ec1f50c0a70c4b4074a67f6b8e3a51dfe026b238b085"
    hash2       = "46c521beb23d37cfa4d60cfcab38c941734971fe3102123b7e4c2813544d39b6"
    hash3       = "cc3d236edb3b45a767b438fa21243a07176d6f5def724e03e45aca76b3127054"

  strings:
    $s1 = "Pu\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"NKq\";})(),(functi" ascii
    $s2 = "\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"GNm\";})(),(function " ascii
    $s3 = "nction fuck(){return \"Dc\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"Yk\";})(),(function fuck(){retur" ascii
    $s4 = "fuck(){return \"Tv\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"Fv\"" ascii
    $s5 = "n \"MIl\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"IPu\";})(),(f" ascii
    $s6 = "ck(){return \"Ug\";})(),(function fuck(){return \"UXf\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"NKq\"" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}