rule TTP_XOR_QUAD_CurrentVersionRun_df0a {
  strings:
    $key_df0a = { 8c 65 [2] a8 6b [2] 83 47 [2] ad 65 [2] b9 7e [2] b6 64 [2] a8 79 [2] aa 78 [2] b1 7e [2] ad 79 [2] b1 56 }

  condition:
    any of them
}