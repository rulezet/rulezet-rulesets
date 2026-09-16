rule TTP_XOR_QUAD_CurrentVersionRun_df74 {
  strings:
    $key_df74 = { 8c 1b [2] a8 15 [2] 83 39 [2] ad 1b [2] b9 00 [2] b6 1a [2] a8 07 [2] aa 06 [2] b1 00 [2] ad 07 [2] b1 28 }

  condition:
    any of them
}