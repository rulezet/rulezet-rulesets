rule TTP_XOR_QUAD_CurrentVersionRun_c194 {
  strings:
    $key_c194 = { 92 fb [2] b6 f5 [2] 9d d9 [2] b3 fb [2] a7 e0 [2] a8 fa [2] b6 e7 [2] b4 e6 [2] af e0 [2] b3 e7 [2] af c8 }

  condition:
    any of them
}