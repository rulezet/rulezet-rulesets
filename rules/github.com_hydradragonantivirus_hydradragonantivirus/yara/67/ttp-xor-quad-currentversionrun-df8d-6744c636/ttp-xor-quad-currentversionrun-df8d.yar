rule TTP_XOR_QUAD_CurrentVersionRun_df8d {
  strings:
    $key_df8d = { 8c e2 [2] a8 ec [2] 83 c0 [2] ad e2 [2] b9 f9 [2] b6 e3 [2] a8 fe [2] aa ff [2] b1 f9 [2] ad fe [2] b1 d1 }

  condition:
    any of them
}