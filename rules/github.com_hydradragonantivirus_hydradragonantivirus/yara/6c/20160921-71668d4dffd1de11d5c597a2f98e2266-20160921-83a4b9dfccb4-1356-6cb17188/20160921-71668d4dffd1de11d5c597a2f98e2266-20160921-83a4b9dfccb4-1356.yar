rule _20160921_71668d4dffd1de11d5c597a2f98e2266_20160921_83a4b9dfccb4_1356 {
  meta:
    description = "datamaliciousorder - from files 20160921_71668d4dffd1de11d5c597a2f98e2266.js, 20160921_83a4b9dfccb435ab7121b53e70b2bb23.js, 20160921_be882ab89423f06a9e76ba0cb72775fe.js, 20160921_dc989bc33de845eef9826b241e933829.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d9bf036d8b4743496b663218b8ff488676bee9250e9706c1179536db46cbba61"
    hash2       = "ad277513de073e1dfeba70577234c4da10406e1298f5253b5cf48893971016ed"
    hash3       = "fe4f2a5579ff9cbd713377a0d5f78bb0c6c30247b6f455ccdb4014a7c298c978"
    hash4       = "780c5e07d33732406de5b51436310fbaacb6d3c6fdcb8d9fa40733ae6e903508"

  strings:
    $s1  = "{return \"Qz\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"RLk\";})(),(function f000(){return \"Mc\";})(" ascii
    $s2  = "turn \"GGn\";})(),(function f000(){return \"Qp\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"IAa\";})()," ascii
    $s3  = "n f000(){return \"OUx\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"ZIi\";})(),(function f000(){return " ascii
    $s4  = "(function f000(){return \"DNa\";})(),(function f000(){return \"Sj\";})(),(function f000(){return \"Qj\";})(),(function f000(){re" ascii
    $s5  = ";})(),(function f000(){return \"Mt\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"TRc\";})(),(function f00" ascii
    $s6  = "nction f000(){return \"OUx\";})(),(function f000(){return \"SEo\";})(),(function f000(){return \"Nv\";})(),(function f000(){retu" ascii
    $s7  = "000(){return \"PTs\";})(),(function f000(){return \"Uo\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"Yi\"" ascii
    $s8  = "function f000(){return \"GGn\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"Mt\";})(),(function f000(){re" ascii
    $s9  = "on f000(){return \"Lo\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){return " ascii
    $s10 = "Yi\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"DIa\";})(),(functi" ascii
    $s11 = "on f000(){return \"Go\";})(),(function f000(){return \"NYh\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"" ascii
    $s12 = "urn \"Qa\";})(),(function f000(){return \"OMd\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"KXg\";})(),(" ascii
    $s13 = "f000(){return \"ZGq\";})(),(function f000(){return \"Nx\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"GG" ascii
    $s14 = "Wy\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"IAa\";})(),(function f000(){return \"Nv\";})(),(functio" ascii
    $s15 = "})(),(function f000(){return \"OUx\";})(),(function f000(){return \"IAa\";})(),(function f000(){return \"TKp\";})(),(function f0" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}