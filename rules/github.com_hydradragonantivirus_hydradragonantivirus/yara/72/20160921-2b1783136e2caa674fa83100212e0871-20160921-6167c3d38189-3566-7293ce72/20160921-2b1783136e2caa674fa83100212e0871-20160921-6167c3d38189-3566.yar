rule _20160921_2b1783136e2caa674fa83100212e0871_20160921_6167c3d38189_3566 {
  meta:
    description = "datamaliciousorder - from files 20160921_2b1783136e2caa674fa83100212e0871.js, 20160921_6167c3d38189e7b1134d16083ffbd574.js, 20160921_68e1fc90afca497654d8f771197c2097.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4f4f696f319827ea3bc8e0b927eddbd7a588f390148cae3276f1573d816d8889"
    hash2       = "02d7a73acd6af9940f585a0e89095467489ba0ac094eb93050d43dab5745e5bd"
    hash3       = "2dfe35f2d9bfd20a5e4771207c1627566795391c957d7b630cc669d3d8856ffd"

  strings:
    $s1 = ";})(),(function f000(){return \"DNa\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"DNa\";})(),(function f0" ascii
    $s2 = " f000(){return \"OUx\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"DNa\";})(),(function f000(){return \"" ascii
    $s3 = "f000(){return \"Yi\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"KXg" ascii
    $s4 = "00(){return \"RPt\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb" ascii
    $s5 = ")(),(function f000(){return \"KXg\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"XTn\";})(),(function f00" ascii
    $s6 = "tion f000(){return \"PTs\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"TRc\";})(),(function f000(){return" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}