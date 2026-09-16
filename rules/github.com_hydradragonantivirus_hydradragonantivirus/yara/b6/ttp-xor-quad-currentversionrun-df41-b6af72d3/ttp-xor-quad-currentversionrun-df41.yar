rule TTP_XOR_QUAD_CurrentVersionRun_df41 {
  strings:
    $key_df41 = { 8c 2e [2] a8 20 [2] 83 0c [2] ad 2e [2] b9 35 [2] b6 2f [2] a8 32 [2] aa 33 [2] b1 35 [2] ad 32 [2] b1 1d }

  condition:
    any of them
}