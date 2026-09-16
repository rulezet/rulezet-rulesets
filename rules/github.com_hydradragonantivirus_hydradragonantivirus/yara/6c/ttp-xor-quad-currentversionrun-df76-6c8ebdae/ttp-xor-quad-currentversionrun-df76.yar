rule TTP_XOR_QUAD_CurrentVersionRun_df76 {
  strings:
    $key_df76 = { 8c 19 [2] a8 17 [2] 83 3b [2] ad 19 [2] b9 02 [2] b6 18 [2] a8 05 [2] aa 04 [2] b1 02 [2] ad 05 [2] b1 2a }

  condition:
    any of them
}