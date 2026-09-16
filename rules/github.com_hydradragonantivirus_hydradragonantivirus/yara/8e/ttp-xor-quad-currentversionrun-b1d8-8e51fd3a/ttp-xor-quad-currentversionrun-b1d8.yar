rule TTP_XOR_QUAD_CurrentVersionRun_b1d8 {
  strings:
    $key_b1d8 = { e2 b7 [2] c6 b9 [2] ed 95 [2] c3 b7 [2] d7 ac [2] d8 b6 [2] c6 ab [2] c4 aa [2] df ac [2] c3 ab [2] df 84 }

  condition:
    any of them
}