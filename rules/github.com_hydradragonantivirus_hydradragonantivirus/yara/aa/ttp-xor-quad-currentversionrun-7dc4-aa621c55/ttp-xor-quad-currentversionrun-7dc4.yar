rule TTP_XOR_QUAD_CurrentVersionRun_7dc4 {
  strings:
    $key_7dc4 = { 2e ab [2] 0a a5 [2] 21 89 [2] 0f ab [2] 1b b0 [2] 14 aa [2] 0a b7 [2] 08 b6 [2] 13 b0 [2] 0f b7 [2] 13 98 }

  condition:
    any of them
}