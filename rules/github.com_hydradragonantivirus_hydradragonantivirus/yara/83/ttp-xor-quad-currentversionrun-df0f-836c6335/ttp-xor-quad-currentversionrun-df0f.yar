rule TTP_XOR_QUAD_CurrentVersionRun_df0f {
  strings:
    $key_df0f = { 8c 60 [2] a8 6e [2] 83 42 [2] ad 60 [2] b9 7b [2] b6 61 [2] a8 7c [2] aa 7d [2] b1 7b [2] ad 7c [2] b1 53 }

  condition:
    any of them
}