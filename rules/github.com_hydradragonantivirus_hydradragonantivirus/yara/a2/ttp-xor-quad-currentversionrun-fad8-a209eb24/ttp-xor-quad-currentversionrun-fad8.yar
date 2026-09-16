rule TTP_XOR_QUAD_CurrentVersionRun_fad8 {
  strings:
    $key_fad8 = { a9 b7 [2] 8d b9 [2] a6 95 [2] 88 b7 [2] 9c ac [2] 93 b6 [2] 8d ab [2] 8f aa [2] 94 ac [2] 88 ab [2] 94 84 }

  condition:
    any of them
}