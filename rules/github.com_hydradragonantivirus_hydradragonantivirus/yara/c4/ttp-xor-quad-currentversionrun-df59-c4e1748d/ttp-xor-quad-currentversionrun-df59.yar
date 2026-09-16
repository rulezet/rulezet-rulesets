rule TTP_XOR_QUAD_CurrentVersionRun_df59 {
  strings:
    $key_df59 = { 8c 36 [2] a8 38 [2] 83 14 [2] ad 36 [2] b9 2d [2] b6 37 [2] a8 2a [2] aa 2b [2] b1 2d [2] ad 2a [2] b1 05 }

  condition:
    any of them
}