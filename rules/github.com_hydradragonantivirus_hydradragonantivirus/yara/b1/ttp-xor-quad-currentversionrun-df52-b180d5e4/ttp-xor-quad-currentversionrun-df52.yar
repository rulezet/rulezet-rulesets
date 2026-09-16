rule TTP_XOR_QUAD_CurrentVersionRun_df52 {
  strings:
    $key_df52 = { 8c 3d [2] a8 33 [2] 83 1f [2] ad 3d [2] b9 26 [2] b6 3c [2] a8 21 [2] aa 20 [2] b1 26 [2] ad 21 [2] b1 0e }

  condition:
    any of them
}