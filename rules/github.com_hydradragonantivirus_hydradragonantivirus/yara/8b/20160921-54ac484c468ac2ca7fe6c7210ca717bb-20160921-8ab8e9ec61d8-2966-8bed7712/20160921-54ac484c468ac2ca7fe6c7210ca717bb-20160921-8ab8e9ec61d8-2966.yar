rule _20160921_54ac484c468ac2ca7fe6c7210ca717bb_20160921_8ab8e9ec61d8_2966 {
  meta:
    description = "datamaliciousorder - from files 20160921_54ac484c468ac2ca7fe6c7210ca717bb.js, 20160921_8ab8e9ec61d829b3b36dc8e0cbc3b477.js, 20160921_e30a7fc515c8c3fe0dd9b1892df8c5ac.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5b883334540a4216b3582d1f2fa0a27f21b9c64a87944c8e58d9fab0f609eef3"
    hash2       = "6302a5443fa0c0309aa33e24b90ed81d05258a2a800cda52321e903fc44e0494"
    hash3       = "2db3499efc418559f17a0414ed3156ee8f0a83f7ca0cb04fe1e2d403c9f22306"

  strings:
    $s1 = "ction f000(){return \"WIj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Vu\";})(),(function f000(){retur" ascii
    $s2 = "function f000(){return \"SGs\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"Zj\";})(),(function f000(){ret" ascii
    $s3 = ")(),(function f000(){return \"DYs\";})(),(function f000(){return \"YTp\";})(),(function f000(){return \"Yi\";})(),(function f000" ascii
    $s4 = "n f000(){return \"YTp\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"DIa\";})(),(function f000(){return " ascii
    $s5 = "rn \"Zj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Rh\";})(),(function f000(){return \"DYx\";})(),(fu" ascii
    $s6 = "eturn \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"RLk\";})(),(function f000(){return \"IPu\";})(" ascii
    $s7 = "turn \"GGn\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"IPu\";})(),(function f000(){return \"Lp\";})()," ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}