rule TTP_XOR_QUAD_CurrentVersionRun_df1c {
  strings:
    $key_df1c = { 8c 73 [2] a8 7d [2] 83 51 [2] ad 73 [2] b9 68 [2] b6 72 [2] a8 6f [2] aa 6e [2] b1 68 [2] ad 6f [2] b1 40 }

  condition:
    any of them
}