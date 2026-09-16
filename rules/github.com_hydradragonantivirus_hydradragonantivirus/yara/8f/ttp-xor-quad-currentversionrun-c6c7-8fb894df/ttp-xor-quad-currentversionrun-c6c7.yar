rule TTP_XOR_QUAD_CurrentVersionRun_c6c7 {
  strings:
    $key_c6c7 = { 95 a8 [2] b1 a6 [2] 9a 8a [2] b4 a8 [2] a0 b3 [2] af a9 [2] b1 b4 [2] b3 b5 [2] a8 b3 [2] b4 b4 [2] a8 9b }

  condition:
    any of them
}