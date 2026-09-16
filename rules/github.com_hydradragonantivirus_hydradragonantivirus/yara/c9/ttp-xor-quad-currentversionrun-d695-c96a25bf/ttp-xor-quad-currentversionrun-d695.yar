rule TTP_XOR_QUAD_CurrentVersionRun_d695 {
  strings:
    $key_d695 = { 85 fa [2] a1 f4 [2] 8a d8 [2] a4 fa [2] b0 e1 [2] bf fb [2] a1 e6 [2] a3 e7 [2] b8 e1 [2] a4 e6 [2] b8 c9 }

  condition:
    any of them
}