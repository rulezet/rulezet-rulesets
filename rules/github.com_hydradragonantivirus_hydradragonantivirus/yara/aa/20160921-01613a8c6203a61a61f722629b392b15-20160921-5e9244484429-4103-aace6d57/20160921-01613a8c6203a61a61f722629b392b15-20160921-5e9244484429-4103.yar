rule _20160921_01613a8c6203a61a61f722629b392b15_20160921_5e9244484429_4103 {
  meta:
    description = "datamaliciousorder - from files 20160921_01613a8c6203a61a61f722629b392b15.js, 20160921_5e9244484429cd897ec88fe97140c29c.js, 20160921_87ced6523e47b3b752b2353107bc989a.js, 20160921_945a46518061bd8e157aed251e0ffa9e.js, 20160921_d03dc2f478ae343430b4a6dbcc9d6c08.js, 20160921_e3aa4388897e55faa45b78b5304a0796.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7c3ee763f1740e8bc6ded9772aabbe3d3805d8cf2a023e0289a9b8a1a42624b7"
    hash2       = "002e6ee9d0d9e7f54ead7f8981f20be210819f7a75c52e3d1e91de2fd03ada17"
    hash3       = "46c521beb23d37cfa4d60cfcab38c941734971fe3102123b7e4c2813544d39b6"
    hash4       = "cc3d236edb3b45a767b438fa21243a07176d6f5def724e03e45aca76b3127054"
    hash5       = "dd1077874fb7f556e5acfe2ff0c2ed6b6c203fcdf442119ca307096446d90cd4"
    hash6       = "2891f4105f11c496e2a838e51e47950b803da8c03fe0cd132c2ad23839c0ca37"

  strings:
    $s1 = "tion fuck(){return \"MBg\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){retur" ascii
    $s2 = "){return \"Ar\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"Np\";})" ascii
    $s3 = "function fuck(){return \"IPu\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){r" ascii
    $s4 = "return \"ADy\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"IPu\";})" ascii
    $s5 = "ck(){return \"Vb\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"LLv" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}