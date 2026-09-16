rule TTP_XOR_QUAD_CurrentVersionRun_5dc9 {
  strings:
    $key_5dc9 = { 0e a6 [2] 2a a8 [2] 01 84 [2] 2f a6 [2] 3b bd [2] 34 a7 [2] 2a ba [2] 28 bb [2] 33 bd [2] 2f ba [2] 33 95 }

  condition:
    any of them
}