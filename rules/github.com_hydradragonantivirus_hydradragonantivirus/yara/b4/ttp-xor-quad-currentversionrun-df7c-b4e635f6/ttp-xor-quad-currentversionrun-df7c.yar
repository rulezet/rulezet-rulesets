rule TTP_XOR_QUAD_CurrentVersionRun_df7c {
  strings:
    $key_df7c = { 8c 13 [2] a8 1d [2] 83 31 [2] ad 13 [2] b9 08 [2] b6 12 [2] a8 0f [2] aa 0e [2] b1 08 [2] ad 0f [2] b1 20 }

  condition:
    any of them
}