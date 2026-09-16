rule TTP_XOR_QUAD_CurrentVersionRun_df22 {
  strings:
    $key_df22 = { 8c 4d [2] a8 43 [2] 83 6f [2] ad 4d [2] b9 56 [2] b6 4c [2] a8 51 [2] aa 50 [2] b1 56 [2] ad 51 [2] b1 7e }

  condition:
    any of them
}