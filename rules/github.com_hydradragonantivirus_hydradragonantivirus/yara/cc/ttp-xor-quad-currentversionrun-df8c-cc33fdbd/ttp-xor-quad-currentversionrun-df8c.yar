rule TTP_XOR_QUAD_CurrentVersionRun_df8c {
  strings:
    $key_df8c = { 8c e3 [2] a8 ed [2] 83 c1 [2] ad e3 [2] b9 f8 [2] b6 e2 [2] a8 ff [2] aa fe [2] b1 f8 [2] ad ff [2] b1 d0 }

  condition:
    any of them
}