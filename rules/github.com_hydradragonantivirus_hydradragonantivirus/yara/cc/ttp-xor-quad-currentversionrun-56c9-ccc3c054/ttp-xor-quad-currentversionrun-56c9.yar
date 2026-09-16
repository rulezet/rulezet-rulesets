rule TTP_XOR_QUAD_CurrentVersionRun_56c9 {
  strings:
    $key_56c9 = { 05 a6 [2] 21 a8 [2] 0a 84 [2] 24 a6 [2] 30 bd [2] 3f a7 [2] 21 ba [2] 23 bb [2] 38 bd [2] 24 ba [2] 38 95 }

  condition:
    any of them
}