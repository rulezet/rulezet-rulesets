rule TTP_XOR_QUAD_CurrentVersionRun_df5d {
  strings:
    $key_df5d = { 8c 32 [2] a8 3c [2] 83 10 [2] ad 32 [2] b9 29 [2] b6 33 [2] a8 2e [2] aa 2f [2] b1 29 [2] ad 2e [2] b1 01 }

  condition:
    any of them
}