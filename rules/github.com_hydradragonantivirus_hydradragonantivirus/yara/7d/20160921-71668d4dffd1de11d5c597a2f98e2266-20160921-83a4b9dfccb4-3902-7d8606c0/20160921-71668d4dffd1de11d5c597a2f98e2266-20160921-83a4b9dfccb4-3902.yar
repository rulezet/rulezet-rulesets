rule _20160921_71668d4dffd1de11d5c597a2f98e2266_20160921_83a4b9dfccb4_3902 {
  meta:
    description = "datamaliciousorder - from files 20160921_71668d4dffd1de11d5c597a2f98e2266.js, 20160921_83a4b9dfccb435ab7121b53e70b2bb23.js, 20160921_dc989bc33de845eef9826b241e933829.js, 20160921_e59567324a545ca23bf9e3ba990b6526.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d9bf036d8b4743496b663218b8ff488676bee9250e9706c1179536db46cbba61"
    hash2       = "ad277513de073e1dfeba70577234c4da10406e1298f5253b5cf48893971016ed"
    hash3       = "780c5e07d33732406de5b51436310fbaacb6d3c6fdcb8d9fa40733ae6e903508"
    hash4       = "ce1d8f63fc8c7b91e97f36fa89b000d70fc284d08682ca3a91ee6c2a4e6e2c72"

  strings:
    $s1 = " f000(){return \"Wy\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"G" ascii
    $s2 = "on f000(){return \"ZGq\";})(),(function f000(){return \"Sq\";})(),(function f000(){return \"GGn\";})(),(function f000(){return " ascii
    $s3 = "{return \"Um\";})(),(function f000(){return \"Mc\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"GGn\";})(" ascii
    $s4 = "000(){return \"GGn\";})(),(function f000(){return \"RLk\";})(),(function f000(){return \"Rh\";})(),(function f000(){return \"Qz" ascii
    $s5 = "RLk\";})(),(function f000(){return \"TKp\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";})(),(funct" ascii
    $s6 = "n\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"SEo\";})(),(function f000(){return \"Sq\";})(),(function" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}