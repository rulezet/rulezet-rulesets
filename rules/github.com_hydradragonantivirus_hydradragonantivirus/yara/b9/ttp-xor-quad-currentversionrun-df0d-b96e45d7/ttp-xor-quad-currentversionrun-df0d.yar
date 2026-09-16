rule TTP_XOR_QUAD_CurrentVersionRun_df0d {
  strings:
    $key_df0d = { 8c 62 [2] a8 6c [2] 83 40 [2] ad 62 [2] b9 79 [2] b6 63 [2] a8 7e [2] aa 7f [2] b1 79 [2] ad 7e [2] b1 51 }

  condition:
    any of them
}