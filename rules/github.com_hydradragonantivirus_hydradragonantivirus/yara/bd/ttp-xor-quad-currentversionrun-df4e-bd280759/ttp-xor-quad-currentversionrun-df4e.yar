rule TTP_XOR_QUAD_CurrentVersionRun_df4e {
  strings:
    $key_df4e = { 8c 21 [2] a8 2f [2] 83 03 [2] ad 21 [2] b9 3a [2] b6 20 [2] a8 3d [2] aa 3c [2] b1 3a [2] ad 3d [2] b1 12 }

  condition:
    any of them
}