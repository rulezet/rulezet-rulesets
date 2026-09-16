rule TTP_XOR_QUAD_CurrentVersionRun_df5a {
  strings:
    $key_df5a = { 8c 35 [2] a8 3b [2] 83 17 [2] ad 35 [2] b9 2e [2] b6 34 [2] a8 29 [2] aa 28 [2] b1 2e [2] ad 29 [2] b1 06 }

  condition:
    any of them
}