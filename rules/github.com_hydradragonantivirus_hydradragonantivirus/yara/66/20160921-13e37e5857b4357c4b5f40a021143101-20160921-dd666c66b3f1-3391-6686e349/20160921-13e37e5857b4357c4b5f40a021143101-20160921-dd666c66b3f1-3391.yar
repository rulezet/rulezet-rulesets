rule _20160921_13e37e5857b4357c4b5f40a021143101_20160921_dd666c66b3f1_3391 {
  meta:
    description = "datamaliciousorder - from files 20160921_13e37e5857b4357c4b5f40a021143101.js, 20160921_dd666c66b3f13d3a71b957c0e646c0a0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bd94ae3a0c3b8dadcaba65cdd5f58ebd19d616ac5679af1b7891e5bf26889265"
    hash2       = "77e753e21a464bef9fad04f7d41ce8b192c797808ff1b22efe474c612c25f2b2"

  strings:
    $s1 = "eturn \"Lp\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"TRc\";})(),(" ascii
    $s2 = "n \"Ot\";})(),(function f000(){return \"Ot\";})(),(function f000(){return \"DNa\";})(),(function f000(){return \"Lo\";})(),(func" ascii
    $s3 = "000(){return \"OUx\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"GGn" ascii
    $s4 = "nction f000(){return \"Vu\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"TKl\";})(),(function f000(){retu" ascii
    $s5 = "function f000(){return \"Ut\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Vj\";})(),(function f000(){ret" ascii
    $s6 = "return \"DNa\";})(),(function f000(){return \"Nx\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";})(" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}