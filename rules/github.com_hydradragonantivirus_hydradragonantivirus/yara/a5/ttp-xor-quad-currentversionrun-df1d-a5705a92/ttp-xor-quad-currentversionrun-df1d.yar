rule TTP_XOR_QUAD_CurrentVersionRun_df1d {
  strings:
    $key_df1d = { 8c 72 [2] a8 7c [2] 83 50 [2] ad 72 [2] b9 69 [2] b6 73 [2] a8 6e [2] aa 6f [2] b1 69 [2] ad 6e [2] b1 41 }

  condition:
    any of them
}