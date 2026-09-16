rule TTP_XOR_QUAD_CurrentVersionRun_df65 {
  strings:
    $key_df65 = { 8c 0a [2] a8 04 [2] 83 28 [2] ad 0a [2] b9 11 [2] b6 0b [2] a8 16 [2] aa 17 [2] b1 11 [2] ad 16 [2] b1 39 }

  condition:
    any of them
}