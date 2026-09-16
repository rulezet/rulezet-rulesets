rule _20160921_4cbbeff2b84f01cc3ab55f4eb29babb2_20160921_5a42d0e1880d_5129 {
  meta:
    description = "datamaliciousorder - from files 20160921_4cbbeff2b84f01cc3ab55f4eb29babb2.js, 20160921_5a42d0e1880d178346694a30bc112076.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "698c46439ef391a98b04ac1a2759ff8a84b30a9c444a7575c5290eb0aa4b66b9"
    hash2       = "ca8e81eec437e87b27dedb202751f13e736aa092e78fffde5fbf40616f2e3738"

  strings:
    $s1 = "(),(function fuck(){return \"USf\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"LGo\";})(),(function fuck(" ascii
    $s2 = "uck(){return \"XHj\";})(),(function fuck(){return \"GWo\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"OQ" ascii
    $s3 = "turn \"NKq\";})(),(function fuck(){return \"ILp\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"GNm\";})()" ascii
    $s4 = ",(function fuck(){return \"USf\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){r" ascii
    $s5 = " fuck(){return \"USf\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}