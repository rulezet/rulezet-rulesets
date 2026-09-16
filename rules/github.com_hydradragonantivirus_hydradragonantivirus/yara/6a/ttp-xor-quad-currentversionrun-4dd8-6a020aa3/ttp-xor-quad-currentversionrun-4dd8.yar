rule TTP_XOR_QUAD_CurrentVersionRun_4dd8 {
  strings:
    $key_4dd8 = { 1e b7 [2] 3a b9 [2] 11 95 [2] 3f b7 [2] 2b ac [2] 24 b6 [2] 3a ab [2] 38 aa [2] 23 ac [2] 3f ab [2] 23 84 }

  condition:
    any of them
}