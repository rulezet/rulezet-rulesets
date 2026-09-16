rule TTP_XOR_QUAD_CurrentVersionRun_df20 {
  strings:
    $key_df20 = { 8c 4f [2] a8 41 [2] 83 6d [2] ad 4f [2] b9 54 [2] b6 4e [2] a8 53 [2] aa 52 [2] b1 54 [2] ad 53 [2] b1 7c }

  condition:
    any of them
}