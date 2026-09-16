rule TTP_XOR_QUAD_CurrentVersionRun_df14 {
  strings:
    $key_df14 = { 8c 7b [2] a8 75 [2] 83 59 [2] ad 7b [2] b9 60 [2] b6 7a [2] a8 67 [2] aa 66 [2] b1 60 [2] ad 67 [2] b1 48 }

  condition:
    any of them
}