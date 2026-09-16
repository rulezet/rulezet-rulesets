rule _20160921_17bf61ad904bb1d3a22ca03d861f889f_20160921_87ced6523e47_2746 {
  meta:
    description = "datamaliciousorder - from files 20160921_17bf61ad904bb1d3a22ca03d861f889f.js, 20160921_87ced6523e47b3b752b2353107bc989a.js, 20160921_945a46518061bd8e157aed251e0ffa9e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3ad9770f05718e622431ef5405e0a702ec2484ecc5b434b1a634c99b480bc855"
    hash2       = "46c521beb23d37cfa4d60cfcab38c941734971fe3102123b7e4c2813544d39b6"
    hash3       = "cc3d236edb3b45a767b438fa21243a07176d6f5def724e03e45aca76b3127054"

  strings:
    $s1 = "on fuck(){return \"IPu\";})(),(function fuck(){return \"Oh\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"" ascii
    $s2 = "urn \"Vf\";})(),(function fuck(){return \"Mw\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"XHj\";})(),(f" ascii
    $s3 = "unction fuck(){return \"Nm\";})(),(function fuck(){return \"SUi\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){ret" ascii
    $s4 = "Qr\";})(),(function fuck(){return \"Et\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"NKq\";})(),(functio" ascii
    $s5 = ",(function fuck(){return \"USf\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"Et\";})(),(function fuck(){" ascii
    $s6 = "(function fuck(){return \"Et\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){r" ascii
    $s7 = "on fuck(){return \"Et\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return " ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}