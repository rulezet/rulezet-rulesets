rule TTP_XOR_QUAD_CurrentVersionRun_df54 {
  strings:
    $key_df54 = { 8c 3b [2] a8 35 [2] 83 19 [2] ad 3b [2] b9 20 [2] b6 3a [2] a8 27 [2] aa 26 [2] b1 20 [2] ad 27 [2] b1 08 }

  condition:
    any of them
}