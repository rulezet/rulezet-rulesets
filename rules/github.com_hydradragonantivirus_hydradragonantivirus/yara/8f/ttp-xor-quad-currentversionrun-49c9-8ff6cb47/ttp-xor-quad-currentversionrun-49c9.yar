rule TTP_XOR_QUAD_CurrentVersionRun_49c9 {
  strings:
    $key_49c9 = { 1a a6 [2] 3e a8 [2] 15 84 [2] 3b a6 [2] 2f bd [2] 20 a7 [2] 3e ba [2] 3c bb [2] 27 bd [2] 3b ba [2] 27 95 }

  condition:
    any of them
}