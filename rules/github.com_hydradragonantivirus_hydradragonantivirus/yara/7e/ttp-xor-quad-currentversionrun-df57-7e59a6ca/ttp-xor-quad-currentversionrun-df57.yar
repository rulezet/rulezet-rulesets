rule TTP_XOR_QUAD_CurrentVersionRun_df57 {
  strings:
    $key_df57 = { 8c 38 [2] a8 36 [2] 83 1a [2] ad 38 [2] b9 23 [2] b6 39 [2] a8 24 [2] aa 25 [2] b1 23 [2] ad 24 [2] b1 0b }

  condition:
    any of them
}