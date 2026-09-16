rule TTP_XOR_QUAD_CurrentVersionRun_df6e {
  strings:
    $key_df6e = { 8c 01 [2] a8 0f [2] 83 23 [2] ad 01 [2] b9 1a [2] b6 00 [2] a8 1d [2] aa 1c [2] b1 1a [2] ad 1d [2] b1 32 }

  condition:
    any of them
}