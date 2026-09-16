rule _20160921_052f92106046138b3c82e05878edd3a8_20160921_6bf1e6b71f68_1638 {
  meta:
    description = "datamaliciousorder - from files 20160921_052f92106046138b3c82e05878edd3a8.js, 20160921_6bf1e6b71f68264911cd95f601a6cc98.js, 20160921_814859e3f9dab39a18edf940d1dd5650.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4812ea00b657b288e9ad51c72fcf466179e82a552fa3278fa9a896cc053c9fdc"
    hash2       = "3380b40f96f91c57b2ab0fcc0353b9938919cdb262f565dd84233769eb1a8842"
    hash3       = "c61c4f66b5cb5b5fa606db7d7b914cbb3fe4d8f1b8ae72ca6b16b707c575cfb0"

  strings:
    $s1  = "rn \"IPu\";})(),(function fuck(){return \"GJx\";})(),(function fuck(){return \"Et\";})(),(function fuck(){return \"FJs\";})(),(f" ascii
    $s2  = "o\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"Xw\";})(),(function " ascii
    $s3  = "k(){return \"Sx\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"XCr\"" ascii
    $s4  = ",(function fuck(){return \"Xw\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){re" ascii
    $s5  = "return \"Dc\";})(),(function fuck(){return \"ZVi\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"Zy\";})()," ascii
    $s6  = "rn \"Fv\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";})(),(fu" ascii
    $s7  = "{return \"Ug\";})(),(function fuck(){return \"UXf\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"MBg\";})(" ascii
    $s8  = "turn \"MBg\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"GJx\";})(),(function fuck(){return \"Et\";})()," ascii
    $s9  = "n \"XHj\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"Ar\";})(),(function fuck(){return \"IPu\";})(),(fun" ascii
    $s10 = "function fuck(){return \"IPu\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"XCr\";})(),(function fuck(){re" ascii
    $s11 = "rn \"OQr\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"GNm\";})(),(f" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}