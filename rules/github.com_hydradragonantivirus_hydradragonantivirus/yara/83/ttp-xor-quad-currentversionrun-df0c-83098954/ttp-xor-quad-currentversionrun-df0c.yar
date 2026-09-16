rule TTP_XOR_QUAD_CurrentVersionRun_df0c {
  strings:
    $key_df0c = { 8c 63 [2] a8 6d [2] 83 41 [2] ad 63 [2] b9 78 [2] b6 62 [2] a8 7f [2] aa 7e [2] b1 78 [2] ad 7f [2] b1 50 }

  condition:
    any of them
}