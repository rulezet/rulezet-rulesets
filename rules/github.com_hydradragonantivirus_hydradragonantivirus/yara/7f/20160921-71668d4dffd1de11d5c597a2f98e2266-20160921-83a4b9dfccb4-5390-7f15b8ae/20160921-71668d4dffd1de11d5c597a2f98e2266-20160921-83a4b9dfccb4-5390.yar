rule _20160921_71668d4dffd1de11d5c597a2f98e2266_20160921_83a4b9dfccb4_5390 {
  meta:
    description = "datamaliciousorder - from files 20160921_71668d4dffd1de11d5c597a2f98e2266.js, 20160921_83a4b9dfccb435ab7121b53e70b2bb23.js, 20160921_b2002e7f99c6e0351a90c5fe98b8b775.js, 20160921_cbfbdc544b309301bc71d300d7726545.js, 20160921_dc989bc33de845eef9826b241e933829.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d9bf036d8b4743496b663218b8ff488676bee9250e9706c1179536db46cbba61"
    hash2       = "ad277513de073e1dfeba70577234c4da10406e1298f5253b5cf48893971016ed"
    hash3       = "1e6376c7075a97cbb4e180ac5ea89ade4f5170dd182e1014b19fd2ed4aa33345"
    hash4       = "135f44db2fcd47db2f5b9cd01f10f5c892ae119d904f5cb0ea4bbdaafba92963"
    hash5       = "780c5e07d33732406de5b51436310fbaacb6d3c6fdcb8d9fa40733ae6e903508"

  strings:
    $s1 = "n f000(){return \"EZu\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"GGn\";})(),(function f000(){return " ascii
    $s2 = "eturn \"Oh\";})(),(function f000(){return \"Lo\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})()," ascii
    $s3 = "(),(function f000(){return \"Ut\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Sj\";})(),(function f000()" ascii
    $s4 = "ction f000(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Lp\";})(),(function f000(){retur" ascii
    $s5 = "){return \"OUx\";})(),(function f000(){return \"BMj\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"GGn\";}" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}