rule TTP_XOR_QUAD_CurrentVersionRun_d1b7 {
  strings:
    $key_d1b7 = { 82 d8 [2] a6 d6 [2] 8d fa [2] a3 d8 [2] b7 c3 [2] b8 d9 [2] a6 c4 [2] a4 c5 [2] bf c3 [2] a3 c4 [2] bf eb }

  condition:
    any of them
}