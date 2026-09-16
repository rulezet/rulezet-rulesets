rule TTP_XOR_QUAD_CurrentVersionRun_df8e {
  strings:
    $key_df8e = { 8c e1 [2] a8 ef [2] 83 c3 [2] ad e1 [2] b9 fa [2] b6 e0 [2] a8 fd [2] aa fc [2] b1 fa [2] ad fd [2] b1 d2 }

  condition:
    any of them
}