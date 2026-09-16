rule _20160921_37aa38f76e02afb64903280105ce4597_20160921_dd666c66b3f1_3632 {
  meta:
    description = "datamaliciousorder - from files 20160921_37aa38f76e02afb64903280105ce4597.js, 20160921_dd666c66b3f13d3a71b957c0e646c0a0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "768a32c669c193375bb8e7adb97cdbb697cd6f4f09fb5dc67bb63e62b7de29cf"
    hash2       = "77e753e21a464bef9fad04f7d41ce8b192c797808ff1b22efe474c612c25f2b2"

  strings:
    $s1 = "turn \"Yi\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(" ascii
    $s2 = "tion f000(){return \"DYs\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"Sq\";})(),(function f000(){return " ascii
    $s3 = "(function f000(){return \"KXg\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Wb\";})(),(function f000(){r" ascii
    $s4 = "000(){return \"GGn\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"PTi\";})(),(function f000(){return \"Yz" ascii
    $s5 = " \"Kw\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Wb\";})(),(function f000(){return \"TRc\";})(),(func" ascii
    $s6 = "unction f000(){return \"OUx\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"TKl\";})(),(function f000(){ret" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}