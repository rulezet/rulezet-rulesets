rule TTP_XOR_QUAD_CurrentVersionRun_28c9 {
  strings:
    $key_28c9 = { 7b a6 [2] 5f a8 [2] 74 84 [2] 5a a6 [2] 4e bd [2] 41 a7 [2] 5f ba [2] 5d bb [2] 46 bd [2] 5a ba [2] 46 95 }

  condition:
    any of them
}