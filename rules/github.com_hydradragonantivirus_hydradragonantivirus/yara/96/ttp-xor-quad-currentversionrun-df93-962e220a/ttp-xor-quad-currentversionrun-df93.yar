rule TTP_XOR_QUAD_CurrentVersionRun_df93 {
  strings:
    $key_df93 = { 8c fc [2] a8 f2 [2] 83 de [2] ad fc [2] b9 e7 [2] b6 fd [2] a8 e0 [2] aa e1 [2] b1 e7 [2] ad e0 [2] b1 cf }

  condition:
    any of them
}