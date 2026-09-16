rule _20160921_3214ea252f2a25e018a03ee43ce952f5_20160921_87ced6523e47_4860 {
  meta:
    description = "datamaliciousorder - from files 20160921_3214ea252f2a25e018a03ee43ce952f5.js, 20160921_87ced6523e47b3b752b2353107bc989a.js, 20160921_945a46518061bd8e157aed251e0ffa9e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e406c80b4ad80ad1898c09cec0694086bfb24caedb8bc3bb213513d0b4232bd3"
    hash2       = "46c521beb23d37cfa4d60cfcab38c941734971fe3102123b7e4c2813544d39b6"
    hash3       = "cc3d236edb3b45a767b438fa21243a07176d6f5def724e03e45aca76b3127054"

  strings:
    $s1 = "tion fuck(){return \"ZLd\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return" ascii
    $s2 = "){return \"NKq\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"GWo\";" ascii
    $s3 = "n fuck(){return \"UXf\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){return \"I" ascii
    $s4 = "k(){return \"Jh\";})(),(function fuck(){return \"We\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"Et\";}" ascii
    $s5 = "\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"Et\";})(),(function " ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}