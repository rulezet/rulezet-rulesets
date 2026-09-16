rule _20160921_7f829eb25609c6f6d37ef18f9c4f8ad7_20160922_9d6af2734812_1414 {
  meta:
    description = "datamaliciousorder - from files 20160921_7f829eb25609c6f6d37ef18f9c4f8ad7.js, 20160922_9d6af27348126e594fbe29c3cf568591.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cbb0232bbf0751233c3e647bef431987aa4666e8c60b9ff699f55e31318c3e22"
    hash2       = "3634189c93f3a76e0a4df72e631f0715b4b71427c157ca5fe116252ca00f1d9b"

  strings:
    $s1  = "nction f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"IAa\";})(),(function f000(){retu" ascii
    $s2  = "000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Uo\";})(),(function f000(){return \"MJq" ascii
    $s3  = "n \"GGn\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"TKl\";})(),(f" ascii
    $s4  = "})(),(function f000(){return \"KDh\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"NYh\";})(),(function f0" ascii
    $s5  = "0(){return \"Do\";})(),(function f000(){return \"MKa\";})(),(function f000(){return \"Ot\";})(),(function f000(){return \"Rh\";}" ascii
    $s6  = "unction f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Lp\";})(),(function f000(){retu" ascii
    $s7  = "),(function f000(){return \"EZu\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"YTp\";})(),(function f000(" ascii
    $s8  = "\"Lp\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";})(),(funct" ascii
    $s9  = "(),(function f000(){return \"BQb\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"Br\";})(),(function f000()" ascii
    $s10 = "OUx\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"Kw\";})(),(functio" ascii
    $s11 = "turn \"WIj\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"Vu\";})(),(f" ascii
    $s12 = "(),(function f000(){return \"KXg\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"TKl\";})(),(function f000(" ascii
    $s13 = "turn \"GGn\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"HJm\";})(),(function f000(){return \"Oh\";})()," ascii
    $s14 = "turn \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"HJm\";})(),(function f000(){return \"Mt\";})(),(" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}