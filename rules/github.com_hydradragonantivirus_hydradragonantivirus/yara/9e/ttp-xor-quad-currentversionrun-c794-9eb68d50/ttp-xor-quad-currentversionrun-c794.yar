rule TTP_XOR_QUAD_CurrentVersionRun_c794 {
  strings:
    $key_c794 = { 94 fb [2] b0 f5 [2] 9b d9 [2] b5 fb [2] a1 e0 [2] ae fa [2] b0 e7 [2] b2 e6 [2] a9 e0 [2] b5 e7 [2] a9 c8 }

  condition:
    any of them
}