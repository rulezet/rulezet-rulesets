rule TTP_XOR_QUAD_CurrentVersionRun_df9e {
  strings:
    $key_df9e = { 8c f1 [2] a8 ff [2] 83 d3 [2] ad f1 [2] b9 ea [2] b6 f0 [2] a8 ed [2] aa ec [2] b1 ea [2] ad ed [2] b1 c2 }

  condition:
    any of them
}