rule TTP_XOR_QUAD_CurrentVersionRun_df04 {
  strings:
    $key_df04 = { 8c 6b [2] a8 65 [2] 83 49 [2] ad 6b [2] b9 70 [2] b6 6a [2] a8 77 [2] aa 76 [2] b1 70 [2] ad 77 [2] b1 58 }

  condition:
    any of them
}