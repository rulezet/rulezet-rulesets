rule TTP_XOR_QUAD_CurrentVersionRun_76c9 {
  strings:
    $key_76c9 = { 25 a6 [2] 01 a8 [2] 2a 84 [2] 04 a6 [2] 10 bd [2] 1f a7 [2] 01 ba [2] 03 bb [2] 18 bd [2] 04 ba [2] 18 95 }

  condition:
    any of them
}