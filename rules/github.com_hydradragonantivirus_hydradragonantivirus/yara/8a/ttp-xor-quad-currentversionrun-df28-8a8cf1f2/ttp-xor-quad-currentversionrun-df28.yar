rule TTP_XOR_QUAD_CurrentVersionRun_df28 {
  strings:
    $key_df28 = { 8c 47 [2] a8 49 [2] 83 65 [2] ad 47 [2] b9 5c [2] b6 46 [2] a8 5b [2] aa 5a [2] b1 5c [2] ad 5b [2] b1 74 }

  condition:
    any of them
}