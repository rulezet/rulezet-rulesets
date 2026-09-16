rule TTP_XOR_QUAD_CurrentVersionRun_df15 {
  strings:
    $key_df15 = { 8c 7a [2] a8 74 [2] 83 58 [2] ad 7a [2] b9 61 [2] b6 7b [2] a8 66 [2] aa 67 [2] b1 61 [2] ad 66 [2] b1 49 }

  condition:
    any of them
}