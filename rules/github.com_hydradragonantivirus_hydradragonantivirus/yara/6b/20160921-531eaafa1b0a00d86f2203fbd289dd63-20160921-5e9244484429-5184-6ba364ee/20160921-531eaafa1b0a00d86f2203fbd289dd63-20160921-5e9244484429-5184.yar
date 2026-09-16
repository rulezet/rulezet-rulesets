rule _20160921_531eaafa1b0a00d86f2203fbd289dd63_20160921_5e9244484429_5184 {
  meta:
    description = "datamaliciousorder - from files 20160921_531eaafa1b0a00d86f2203fbd289dd63.js, 20160921_5e9244484429cd897ec88fe97140c29c.js, 20160921_6db2cb585eb933d83d07b47d979b00ec.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d28500022264ce61d9d988db6f8ddee46acc7dea6f898510f532ee48f87a0c93"
    hash2       = "002e6ee9d0d9e7f54ead7f8981f20be210819f7a75c52e3d1e91de2fd03ada17"
    hash3       = "b98c5953d102d77c680619bcfd3ba762b3a28a14355f65c479544c745a7c9a12"

  strings:
    $s1 = ")(),(function fuck(){return \"Ot\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"GWo\";})(),(function fuck" ascii
    $s2 = "Ik\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"XHj\";})(),(functi" ascii
    $s3 = ";})(),(function fuck(){return \"Zy\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return \"IPu\";})(),(function fuc" ascii
    $s4 = "turn \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){return \"Sx\";})()," ascii
    $s5 = "rn \"To\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"NKq\";})(),(f" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}