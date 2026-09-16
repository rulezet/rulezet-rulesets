rule _20160921_18e4d81197d615e3008ec96ea25b7dc4_20160921_2b1783136e2c_2751 {
  meta:
    description = "datamaliciousorder - from files 20160921_18e4d81197d615e3008ec96ea25b7dc4.js, 20160921_2b1783136e2caa674fa83100212e0871.js, 20160921_6167c3d38189e7b1134d16083ffbd574.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4b707313cf8ee2fdf903e5516937a17e48e75059c21a08483659705a96da9670"
    hash2       = "4f4f696f319827ea3bc8e0b927eddbd7a588f390148cae3276f1573d816d8889"
    hash3       = "02d7a73acd6af9940f585a0e89095467489ba0ac094eb93050d43dab5745e5bd"

  strings:
    $s1 = "{return \"DNa\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Ut\";})(),(function f000(){return \"GGn\";})" ascii
    $s2 = "unction f000(){return \"KXg\";})(),(function f000(){return \"DNa\";})(),(function f000(){return \"PTs\";})(),(function f000(){re" ascii
    $s3 = "})(),(function f000(){return \"OUx\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"DNa\";})(),(function f0" ascii
    $s4 = "Xg\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"DNa\";})(),(function f000(){return \"TRc\";})(),(functio" ascii
    $s5 = "ction f000(){return \"Qj\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"Zj\";})(),(function f000(){return " ascii
    $s6 = ")(),(function f000(){return \"KXg\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"TRc\";})(),(function f00" ascii
    $s7 = "ion f000(){return \"PTs\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Ut\";})(),(function f000(){return " ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}