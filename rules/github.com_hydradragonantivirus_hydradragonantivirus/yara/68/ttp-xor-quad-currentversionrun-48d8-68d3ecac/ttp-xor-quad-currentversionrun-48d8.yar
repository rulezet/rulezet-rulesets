rule TTP_XOR_QUAD_CurrentVersionRun_48d8 {
  strings:
    $key_48d8 = { 1b b7 [2] 3f b9 [2] 14 95 [2] 3a b7 [2] 2e ac [2] 21 b6 [2] 3f ab [2] 3d aa [2] 26 ac [2] 3a ab [2] 26 84 }

  condition:
    any of them
}