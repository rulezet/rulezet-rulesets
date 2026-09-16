rule TTP_XOR_QUAD_CurrentVersionRun_c6c4 {
  strings:
    $key_c6c4 = { 95 ab [2] b1 a5 [2] 9a 89 [2] b4 ab [2] a0 b0 [2] af aa [2] b1 b7 [2] b3 b6 [2] a8 b0 [2] b4 b7 [2] a8 98 }

  condition:
    any of them
}