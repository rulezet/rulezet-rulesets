rule TTP_XOR_QUAD_CurrentVersionRun_df9a {
  strings:
    $key_df9a = { 8c f5 [2] a8 fb [2] 83 d7 [2] ad f5 [2] b9 ee [2] b6 f4 [2] a8 e9 [2] aa e8 [2] b1 ee [2] ad e9 [2] b1 c6 }

  condition:
    any of them
}