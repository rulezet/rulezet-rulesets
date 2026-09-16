rule TTP_XOR_QUAD_CurrentVersionRun_df11 {
  strings:
    $key_df11 = { 8c 7e [2] a8 70 [2] 83 5c [2] ad 7e [2] b9 65 [2] b6 7f [2] a8 62 [2] aa 63 [2] b1 65 [2] ad 62 [2] b1 4d }

  condition:
    any of them
}