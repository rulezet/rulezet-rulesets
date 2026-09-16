rule TTP_XOR_QUAD_CurrentVersionRun_df13 {
  strings:
    $key_df13 = { 8c 7c [2] a8 72 [2] 83 5e [2] ad 7c [2] b9 67 [2] b6 7d [2] a8 60 [2] aa 61 [2] b1 67 [2] ad 60 [2] b1 4f }

  condition:
    any of them
}