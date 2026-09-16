rule TTP_XOR_QUAD_CurrentVersionRun_df78 {
  strings:
    $key_df78 = { 8c 17 [2] a8 19 [2] 83 35 [2] ad 17 [2] b9 0c [2] b6 16 [2] a8 0b [2] aa 0a [2] b1 0c [2] ad 0b [2] b1 24 }

  condition:
    any of them
}