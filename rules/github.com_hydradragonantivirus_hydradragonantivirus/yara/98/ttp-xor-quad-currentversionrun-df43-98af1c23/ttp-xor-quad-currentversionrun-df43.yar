rule TTP_XOR_QUAD_CurrentVersionRun_df43 {
  strings:
    $key_df43 = { 8c 2c [2] a8 22 [2] 83 0e [2] ad 2c [2] b9 37 [2] b6 2d [2] a8 30 [2] aa 31 [2] b1 37 [2] ad 30 [2] b1 1f }

  condition:
    any of them
}