rule TTP_XOR_QUAD_CurrentVersionRun_58d8 {
  strings:
    $key_58d8 = { 0b b7 [2] 2f b9 [2] 04 95 [2] 2a b7 [2] 3e ac [2] 31 b6 [2] 2f ab [2] 2d aa [2] 36 ac [2] 2a ab [2] 36 84 }

  condition:
    any of them
}