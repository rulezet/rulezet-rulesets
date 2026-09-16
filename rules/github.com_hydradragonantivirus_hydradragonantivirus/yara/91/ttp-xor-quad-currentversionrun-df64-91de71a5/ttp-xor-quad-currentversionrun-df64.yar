rule TTP_XOR_QUAD_CurrentVersionRun_df64 {
  strings:
    $key_df64 = { 8c 0b [2] a8 05 [2] 83 29 [2] ad 0b [2] b9 10 [2] b6 0a [2] a8 17 [2] aa 16 [2] b1 10 [2] ad 17 [2] b1 38 }

  condition:
    any of them
}