rule TTP_XOR_QUAD_CurrentVersionRun_4dc4 {
  strings:
    $key_4dc4 = { 1e ab [2] 3a a5 [2] 11 89 [2] 3f ab [2] 2b b0 [2] 24 aa [2] 3a b7 [2] 38 b6 [2] 23 b0 [2] 3f b7 [2] 23 98 }

  condition:
    any of them
}