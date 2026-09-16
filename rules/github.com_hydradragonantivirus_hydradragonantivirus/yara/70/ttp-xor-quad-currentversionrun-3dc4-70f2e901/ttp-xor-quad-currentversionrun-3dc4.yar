rule TTP_XOR_QUAD_CurrentVersionRun_3dc4 {
  strings:
    $key_3dc4 = { 6e ab [2] 4a a5 [2] 61 89 [2] 4f ab [2] 5b b0 [2] 54 aa [2] 4a b7 [2] 48 b6 [2] 53 b0 [2] 4f b7 [2] 53 98 }

  condition:
    any of them
}