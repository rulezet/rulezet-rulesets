rule TTP_XOR_QUAD_CurrentVersionRun_c6ca {
  strings:
    $key_c6ca = { 95 a5 [2] b1 ab [2] 9a 87 [2] b4 a5 [2] a0 be [2] af a4 [2] b1 b9 [2] b3 b8 [2] a8 be [2] b4 b9 [2] a8 96 }

  condition:
    any of them
}