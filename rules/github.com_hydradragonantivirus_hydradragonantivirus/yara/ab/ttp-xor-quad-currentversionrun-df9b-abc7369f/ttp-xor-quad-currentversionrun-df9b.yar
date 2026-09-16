rule TTP_XOR_QUAD_CurrentVersionRun_df9b {
  strings:
    $key_df9b = { 8c f4 [2] a8 fa [2] 83 d6 [2] ad f4 [2] b9 ef [2] b6 f5 [2] a8 e8 [2] aa e9 [2] b1 ef [2] ad e8 [2] b1 c7 }

  condition:
    any of them
}