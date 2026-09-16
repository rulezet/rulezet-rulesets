rule TTP_XOR_QUAD_CurrentVersionRun_df19 {
  strings:
    $key_df19 = { 8c 76 [2] a8 78 [2] 83 54 [2] ad 76 [2] b9 6d [2] b6 77 [2] a8 6a [2] aa 6b [2] b1 6d [2] ad 6a [2] b1 45 }

  condition:
    any of them
}