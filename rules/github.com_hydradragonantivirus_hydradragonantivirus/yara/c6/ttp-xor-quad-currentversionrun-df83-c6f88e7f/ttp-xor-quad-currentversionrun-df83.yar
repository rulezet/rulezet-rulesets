rule TTP_XOR_QUAD_CurrentVersionRun_df83 {
  strings:
    $key_df83 = { 8c ec [2] a8 e2 [2] 83 ce [2] ad ec [2] b9 f7 [2] b6 ed [2] a8 f0 [2] aa f1 [2] b1 f7 [2] ad f0 [2] b1 df }

  condition:
    any of them
}