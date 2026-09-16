rule TTP_XOR_QUAD_CurrentVersionRun_df3a {
  strings:
    $key_df3a = { 8c 55 [2] a8 5b [2] 83 77 [2] ad 55 [2] b9 4e [2] b6 54 [2] a8 49 [2] aa 48 [2] b1 4e [2] ad 49 [2] b1 66 }

  condition:
    any of them
}