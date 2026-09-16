rule _20160921_6d7b654a484acab4abb3060ebc68a164_20160921_a2f8f3f44ef6_1501 {
  meta:
    description = "datamaliciousorder - from files 20160921_6d7b654a484acab4abb3060ebc68a164.js, 20160921_a2f8f3f44ef6a3341feac8fb57e829ce.js, 20160921_ce3c0604d52e9dc9119cefedfee34385.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2840e0696eacd7118885eaede05c3ef29d9cc682ba227d7797a60be4872d86c9"
    hash2       = "619e82812300e58dd7cd06b8fbcf2f7e3f6757812cc075603c82363ab6481758"
    hash3       = "27a20a400d7aa13737d230acf36a2170494c7da92e72552775d19562ba331fdc"

  strings:
    $s1  = "function fuck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){ret" ascii
    $s2  = "(){return \"OPz\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"Ve\";}" ascii
    $s3  = "ction fuck(){return \"ZLd\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return" ascii
    $s4  = "ion fuck(){return \"MUs\";})(),(function fuck(){return \"KVh\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return " ascii
    $s5  = "Xg\";})(),(function fuck(){return \"UXf\";})(),(function fuck(){return \"DAa\";})(),(function fuck(){return \"Fv\";})(),(functio" ascii
    $s6  = "fuck(){return \"Ar\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"IPu" ascii
    $s7  = " \"Cd\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){return \"QTc\";})(),(function fuck(){return \"Vb\";})(),(funct" ascii
    $s8  = "ck(){return \"Ik\";})(),(function fuck(){return \"Ar\";})(),(function fuck(){return \"KVh\";})(),(function fuck(){return \"MUs\"" ascii
    $s9  = "ck(){return \"Mw\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MBg" ascii
    $s10 = "ction fuck(){return \"XHj\";})(),(function fuck(){return \"Wo0\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){retu" ascii
    $s11 = "x\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){return \"Cd\";})(),(function" ascii
    $s12 = "t\";})(),(function fuck(){return \"QTc\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"IPu\";})(),(function" ascii
    $s13 = "turn \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){return \"Wo0\";})()," ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}