rule TTP_XOR_QUAD_CurrentVersionRun_df50 {
  strings:
    $key_df50 = { 8c 3f [2] a8 31 [2] 83 1d [2] ad 3f [2] b9 24 [2] b6 3e [2] a8 23 [2] aa 22 [2] b1 24 [2] ad 23 [2] b1 0c }

  condition:
    any of them
}