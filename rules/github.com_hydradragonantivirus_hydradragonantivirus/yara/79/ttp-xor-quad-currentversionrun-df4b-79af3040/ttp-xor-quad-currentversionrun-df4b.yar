rule TTP_XOR_QUAD_CurrentVersionRun_df4b {
  strings:
    $key_df4b = { 8c 24 [2] a8 2a [2] 83 06 [2] ad 24 [2] b9 3f [2] b6 25 [2] a8 38 [2] aa 39 [2] b1 3f [2] ad 38 [2] b1 17 }

  condition:
    any of them
}