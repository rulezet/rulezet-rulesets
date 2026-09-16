rule _20160921_03b650867a3952f7709688e58e8232f3_20160921_063094039ef7_3214 {
  meta:
    description = "datamaliciousorder - from files 20160921_03b650867a3952f7709688e58e8232f3.js, 20160921_063094039ef79437a260d3dde960797a.js, 20160921_32a3b245a67cd982da1d38f57645b403.js, 20160921_35613f26ab8269650aa877fd5af3e43b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a775853212fe6663d7c077a64c0d4c851d4b7f261a6c0846b4552b556e12a5fe"
    hash2       = "ce1eb4a08b98ec71f6759f87657e36ddf82182025b3e317c586fb55c186b9e6c"
    hash3       = "9f7e53a243b56341e3d17450083c46ba2a33141b25134577db086128321a8223"
    hash4       = "432da9fcdf6c0d62e24e70562f7949325e57abff120248541ccbdaf091d0a7f3"

  strings:
    $s1 = "(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"Cd\";})(),(function fuck()" ascii
    $s2 = "on fuck(){return \"Np\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"" ascii
    $s3 = "uck(){return \"GJx\";})(),(function fuck(){return \"ZVi\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"IPu" ascii
    $s4 = "eturn \"IRn\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"DWe\";})(),(function fuck(){return \"Ik\";})()" ascii
    $s5 = "n \"CCb\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"XHj\";})(),(fu" ascii
    $s6 = "\"SUi\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";})(),(fun" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}