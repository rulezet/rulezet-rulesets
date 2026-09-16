rule TTP_XOR_QUAD_CurrentVersionRun_df80 {
  strings:
    $key_df80 = { 8c ef [2] a8 e1 [2] 83 cd [2] ad ef [2] b9 f4 [2] b6 ee [2] a8 f3 [2] aa f2 [2] b1 f4 [2] ad f3 [2] b1 dc }

  condition:
    any of them
}