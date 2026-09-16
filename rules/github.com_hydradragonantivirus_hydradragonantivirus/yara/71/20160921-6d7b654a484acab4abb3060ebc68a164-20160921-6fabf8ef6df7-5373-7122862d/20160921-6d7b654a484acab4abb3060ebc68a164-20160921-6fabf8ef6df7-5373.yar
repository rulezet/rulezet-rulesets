rule _20160921_6d7b654a484acab4abb3060ebc68a164_20160921_6fabf8ef6df7_5373 {
  meta:
    description = "datamaliciousorder - from files 20160921_6d7b654a484acab4abb3060ebc68a164.js, 20160921_6fabf8ef6df7ba14509fab6de95d721f.js, 20160921_a2f8f3f44ef6a3341feac8fb57e829ce.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2840e0696eacd7118885eaede05c3ef29d9cc682ba227d7797a60be4872d86c9"
    hash2       = "a6962383b3793edac58fef061128f9047afb39eaa645d3f7977a775ceeb02e56"
    hash3       = "619e82812300e58dd7cd06b8fbcf2f7e3f6757812cc075603c82363ab6481758"

  strings:
    $s1 = "eturn \"ZVi\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MBg\";})(" ascii
    $s2 = ",(function fuck(){return \"Vf\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){r" ascii
    $s3 = "\"MBg\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){return \"AUx\";})(),(fun" ascii
    $s4 = "ction fuck(){return \"IPu\";})(),(function fuck(){return \"XCr\";})(),(function fuck(){return \"Zy\";})(),(function fuck(){retur" ascii
    $s5 = "turn \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DWe\";})(),(function fuck(){return \"Mw\";})()," ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}