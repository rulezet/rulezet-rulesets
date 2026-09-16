rule TTP_XOR_QUAD_CurrentVersionRun_df0e {
  strings:
    $key_df0e = { 8c 61 [2] a8 6f [2] 83 43 [2] ad 61 [2] b9 7a [2] b6 60 [2] a8 7d [2] aa 7c [2] b1 7a [2] ad 7d [2] b1 52 }

  condition:
    any of them
}