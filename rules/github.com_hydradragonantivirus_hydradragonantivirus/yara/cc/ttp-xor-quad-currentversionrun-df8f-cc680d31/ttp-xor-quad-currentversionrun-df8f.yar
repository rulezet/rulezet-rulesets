rule TTP_XOR_QUAD_CurrentVersionRun_df8f {
  strings:
    $key_df8f = { 8c e0 [2] a8 ee [2] 83 c2 [2] ad e0 [2] b9 fb [2] b6 e1 [2] a8 fc [2] aa fd [2] b1 fb [2] ad fc [2] b1 d3 }

  condition:
    any of them
}