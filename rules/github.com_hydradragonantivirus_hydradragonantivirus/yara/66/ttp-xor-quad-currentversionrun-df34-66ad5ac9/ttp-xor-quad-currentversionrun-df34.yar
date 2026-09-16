rule TTP_XOR_QUAD_CurrentVersionRun_df34 {
  strings:
    $key_df34 = { 8c 5b [2] a8 55 [2] 83 79 [2] ad 5b [2] b9 40 [2] b6 5a [2] a8 47 [2] aa 46 [2] b1 40 [2] ad 47 [2] b1 68 }

  condition:
    any of them
}