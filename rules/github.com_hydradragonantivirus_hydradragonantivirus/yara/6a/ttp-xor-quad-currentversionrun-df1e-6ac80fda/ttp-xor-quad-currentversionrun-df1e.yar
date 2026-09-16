rule TTP_XOR_QUAD_CurrentVersionRun_df1e {
  strings:
    $key_df1e = { 8c 71 [2] a8 7f [2] 83 53 [2] ad 71 [2] b9 6a [2] b6 70 [2] a8 6d [2] aa 6c [2] b1 6a [2] ad 6d [2] b1 42 }

  condition:
    any of them
}