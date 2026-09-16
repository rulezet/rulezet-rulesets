rule TTP_XOR_QUAD_CurrentVersionRun_df39 {
  strings:
    $key_df39 = { 8c 56 [2] a8 58 [2] 83 74 [2] ad 56 [2] b9 4d [2] b6 57 [2] a8 4a [2] aa 4b [2] b1 4d [2] ad 4a [2] b1 65 }

  condition:
    any of them
}