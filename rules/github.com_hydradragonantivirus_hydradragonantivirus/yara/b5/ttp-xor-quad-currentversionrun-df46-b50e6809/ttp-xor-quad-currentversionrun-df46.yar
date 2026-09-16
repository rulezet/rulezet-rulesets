rule TTP_XOR_QUAD_CurrentVersionRun_df46 {
  strings:
    $key_df46 = { 8c 29 [2] a8 27 [2] 83 0b [2] ad 29 [2] b9 32 [2] b6 28 [2] a8 35 [2] aa 34 [2] b1 32 [2] ad 35 [2] b1 1a }

  condition:
    any of them
}