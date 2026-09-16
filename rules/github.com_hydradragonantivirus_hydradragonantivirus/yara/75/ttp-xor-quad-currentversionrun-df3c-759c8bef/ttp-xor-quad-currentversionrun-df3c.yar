rule TTP_XOR_QUAD_CurrentVersionRun_df3c {
  strings:
    $key_df3c = { 8c 53 [2] a8 5d [2] 83 71 [2] ad 53 [2] b9 48 [2] b6 52 [2] a8 4f [2] aa 4e [2] b1 48 [2] ad 4f [2] b1 60 }

  condition:
    any of them
}