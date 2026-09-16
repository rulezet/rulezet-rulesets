rule TTP_XOR_QUAD_CurrentVersionRun_df72 {
  strings:
    $key_df72 = { 8c 1d [2] a8 13 [2] 83 3f [2] ad 1d [2] b9 06 [2] b6 1c [2] a8 01 [2] aa 00 [2] b1 06 [2] ad 01 [2] b1 2e }

  condition:
    any of them
}