rule TTP_XOR_QUAD_CurrentVersionRun_df2b {
  strings:
    $key_df2b = { 8c 44 [2] a8 4a [2] 83 66 [2] ad 44 [2] b9 5f [2] b6 45 [2] a8 58 [2] aa 59 [2] b1 5f [2] ad 58 [2] b1 77 }

  condition:
    any of them
}