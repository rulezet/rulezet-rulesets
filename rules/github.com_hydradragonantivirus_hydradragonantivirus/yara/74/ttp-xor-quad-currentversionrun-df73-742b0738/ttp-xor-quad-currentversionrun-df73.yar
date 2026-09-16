rule TTP_XOR_QUAD_CurrentVersionRun_df73 {
  strings:
    $key_df73 = { 8c 1c [2] a8 12 [2] 83 3e [2] ad 1c [2] b9 07 [2] b6 1d [2] a8 00 [2] aa 01 [2] b1 07 [2] ad 00 [2] b1 2f }

  condition:
    any of them
}