rule TTP_XOR_QUAD_CurrentVersionRun_df77 {
  strings:
    $key_df77 = { 8c 18 [2] a8 16 [2] 83 3a [2] ad 18 [2] b9 03 [2] b6 19 [2] a8 04 [2] aa 05 [2] b1 03 [2] ad 04 [2] b1 2b }

  condition:
    any of them
}