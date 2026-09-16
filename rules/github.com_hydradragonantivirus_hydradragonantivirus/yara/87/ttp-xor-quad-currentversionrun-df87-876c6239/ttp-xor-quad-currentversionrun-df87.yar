rule TTP_XOR_QUAD_CurrentVersionRun_df87 {
  strings:
    $key_df87 = { 8c e8 [2] a8 e6 [2] 83 ca [2] ad e8 [2] b9 f3 [2] b6 e9 [2] a8 f4 [2] aa f5 [2] b1 f3 [2] ad f4 [2] b1 db }

  condition:
    any of them
}