rule TTP_XOR_QUAD_CurrentVersionRun_df7d {
  strings:
    $key_df7d = { 8c 12 [2] a8 1c [2] 83 30 [2] ad 12 [2] b9 09 [2] b6 13 [2] a8 0e [2] aa 0f [2] b1 09 [2] ad 0e [2] b1 21 }

  condition:
    any of them
}