rule TTP_XOR_QUAD_CurrentVersionRun_c684 {
  strings:
    $key_c684 = { 95 eb [2] b1 e5 [2] 9a c9 [2] b4 eb [2] a0 f0 [2] af ea [2] b1 f7 [2] b3 f6 [2] a8 f0 [2] b4 f7 [2] a8 d8 }

  condition:
    any of them
}