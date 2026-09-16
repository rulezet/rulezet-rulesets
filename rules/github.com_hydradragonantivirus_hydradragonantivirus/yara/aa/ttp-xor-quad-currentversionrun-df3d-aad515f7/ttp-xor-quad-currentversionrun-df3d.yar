rule TTP_XOR_QUAD_CurrentVersionRun_df3d {
  strings:
    $key_df3d = { 8c 52 [2] a8 5c [2] 83 70 [2] ad 52 [2] b9 49 [2] b6 53 [2] a8 4e [2] aa 4f [2] b1 49 [2] ad 4e [2] b1 61 }

  condition:
    any of them
}