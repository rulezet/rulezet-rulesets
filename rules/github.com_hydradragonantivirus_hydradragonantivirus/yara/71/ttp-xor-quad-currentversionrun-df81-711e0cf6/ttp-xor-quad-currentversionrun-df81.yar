rule TTP_XOR_QUAD_CurrentVersionRun_df81 {
  strings:
    $key_df81 = { 8c ee [2] a8 e0 [2] 83 cc [2] ad ee [2] b9 f5 [2] b6 ef [2] a8 f2 [2] aa f3 [2] b1 f5 [2] ad f2 [2] b1 dd }

  condition:
    any of them
}