rule _20160921_71668d4dffd1de11d5c597a2f98e2266_20160921_83a4b9dfccb4_16 {
  meta:
    description = "datamaliciousorder - from files 20160921_71668d4dffd1de11d5c597a2f98e2266.js, 20160921_83a4b9dfccb435ab7121b53e70b2bb23.js, 20160921_dc989bc33de845eef9826b241e933829.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d9bf036d8b4743496b663218b8ff488676bee9250e9706c1179536db46cbba61"
    hash2       = "ad277513de073e1dfeba70577234c4da10406e1298f5253b5cf48893971016ed"
    hash3       = "780c5e07d33732406de5b51436310fbaacb6d3c6fdcb8d9fa40733ae6e903508"

  strings:
    $s1  = "0(){return \"QDg\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"Lo\";}" ascii
    $s2  = "f000(){return \"Yi\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"SEo\";})(),(function f000(){return \"Km" ascii
    $s3  = "nction f000(){return \"Oe\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"Wh\";})(),(function f000(){return" ascii
    $s4  = "urn \"Iq\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"Uo\";})(),(fu" ascii
    $s5  = "n \"OUx\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"XTn\";})(),(fu" ascii
    $s6  = ",(function f000(){return \"DNa\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"GGn\";})(),(function f000(){" ascii
    $s7  = "f000(){return \"Yi\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Qa" ascii
    $s8  = "00(){return \"ZFe\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"MMz\"" ascii
    $s9  = "n \"IAa\";})(),(function f000(){return \"Sq\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Sj0\";})(),(fu" ascii
    $s10 = "000(){return \"DYx\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"BMj\";})(),(function f000(){return \"TK" ascii
    $s11 = "urn \"ZFe\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Zj\";})(),(" ascii
    $s12 = "\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Zj\";})(),(function " ascii
    $s13 = "urn \"XTn\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"OMd\";})()," ascii
    $s14 = "0(){return \"KXg\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"TRc\";" ascii
    $s15 = "Ij\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"Rh\";})(),(functio" ascii
    $s16 = "turn \"DNa\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"GGn\";})(),(" ascii
    $s17 = "turn \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Um\";})(),(f" ascii
    $s18 = "rn \"GGn\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"SEo\";})(),(function f000(){return \"Yz\";})(),(f" ascii
    $s19 = "turn \"Qa\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"MMz\";})(),(f" ascii
    $s20 = "000(){return \"GGn\";})(),(function f000(){return \"Ut\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Qa" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}