rule TTP_XOR_QUAD_CurrentVersionRun_c6c6 {
  strings:
    $key_c6c6 = { 95 a9 [2] b1 a7 [2] 9a 8b [2] b4 a9 [2] a0 b2 [2] af a8 [2] b1 b5 [2] b3 b4 [2] a8 b2 [2] b4 b5 [2] a8 9a }

  condition:
    any of them
}