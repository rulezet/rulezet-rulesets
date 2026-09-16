rule TTP_XOR_QUAD_CurrentVersionRun_df2f {
  strings:
    $key_df2f = { 8c 40 [2] a8 4e [2] 83 62 [2] ad 40 [2] b9 5b [2] b6 41 [2] a8 5c [2] aa 5d [2] b1 5b [2] ad 5c [2] b1 73 }

  condition:
    any of them
}