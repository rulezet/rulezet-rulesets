rule TTP_XOR_QUAD_CurrentVersionRun_df66 {
  strings:
    $key_df66 = { 8c 09 [2] a8 07 [2] 83 2b [2] ad 09 [2] b9 12 [2] b6 08 [2] a8 15 [2] aa 14 [2] b1 12 [2] ad 15 [2] b1 3a }

  condition:
    any of them
}