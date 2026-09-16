rule TTP_XOR_QUAD_CurrentVersionRun_df16 {
  strings:
    $key_df16 = { 8c 79 [2] a8 77 [2] 83 5b [2] ad 79 [2] b9 62 [2] b6 78 [2] a8 65 [2] aa 64 [2] b1 62 [2] ad 65 [2] b1 4a }

  condition:
    any of them
}