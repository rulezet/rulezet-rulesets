rule _20160921_346ce24842d4c67049d4ae8a4ef57f0b_20160921_71668d4dffd1_3617 {
  meta:
    description = "datamaliciousorder - from files 20160921_346ce24842d4c67049d4ae8a4ef57f0b.js, 20160921_71668d4dffd1de11d5c597a2f98e2266.js, 20160921_83a4b9dfccb435ab7121b53e70b2bb23.js, 20160921_dc989bc33de845eef9826b241e933829.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "24cea6347b33f54d332a2f5000d3f2841a3a09a1270f4da0da530495cac7ac0e"
    hash2       = "d9bf036d8b4743496b663218b8ff488676bee9250e9706c1179536db46cbba61"
    hash3       = "ad277513de073e1dfeba70577234c4da10406e1298f5253b5cf48893971016ed"
    hash4       = "780c5e07d33732406de5b51436310fbaacb6d3c6fdcb8d9fa40733ae6e903508"

  strings:
    $s1 = "})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"PTs\";})(),(function f00" ascii
    $s2 = ")(),(function f000(){return \"GGn\";})(),(function f000(){return \"Go\";})(),(function f000(){return \"PTs\";})(),(function f000" ascii
    $s3 = "})(),(function f000(){return \"Do\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"Zj\";})(),(function f000" ascii
    $s4 = "(){return \"GGn\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Yz\";})" ascii
    $s5 = "\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"Zj\";})(),(function f" ascii
    $s6 = "ction f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"ZFe\";})(),(function f000(){retu" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}