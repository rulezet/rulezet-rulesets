rule TTP_XOR_QUAD_CurrentVersionRun_df75 {
  strings:
    $key_df75 = { 8c 1a [2] a8 14 [2] 83 38 [2] ad 1a [2] b9 01 [2] b6 1b [2] a8 06 [2] aa 07 [2] b1 01 [2] ad 06 [2] b1 29 }

  condition:
    any of them
}