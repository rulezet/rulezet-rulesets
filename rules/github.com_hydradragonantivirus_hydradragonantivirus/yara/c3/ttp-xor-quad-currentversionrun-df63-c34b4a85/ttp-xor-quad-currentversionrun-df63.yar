rule TTP_XOR_QUAD_CurrentVersionRun_df63 {
  strings:
    $key_df63 = { 8c 0c [2] a8 02 [2] 83 2e [2] ad 0c [2] b9 17 [2] b6 0d [2] a8 10 [2] aa 11 [2] b1 17 [2] ad 10 [2] b1 3f }

  condition:
    any of them
}