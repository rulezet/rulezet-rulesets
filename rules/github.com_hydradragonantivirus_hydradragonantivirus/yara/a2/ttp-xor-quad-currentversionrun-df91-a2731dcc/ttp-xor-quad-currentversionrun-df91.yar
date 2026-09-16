rule TTP_XOR_QUAD_CurrentVersionRun_df91 {
  strings:
    $key_df91 = { 8c fe [2] a8 f0 [2] 83 dc [2] ad fe [2] b9 e5 [2] b6 ff [2] a8 e2 [2] aa e3 [2] b1 e5 [2] ad e2 [2] b1 cd }

  condition:
    any of them
}