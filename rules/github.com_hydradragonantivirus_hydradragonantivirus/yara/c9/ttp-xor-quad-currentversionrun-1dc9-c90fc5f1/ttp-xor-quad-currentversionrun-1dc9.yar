rule TTP_XOR_QUAD_CurrentVersionRun_1dc9 {
  strings:
    $key_1dc9 = { 4e a6 [2] 6a a8 [2] 41 84 [2] 6f a6 [2] 7b bd [2] 74 a7 [2] 6a ba [2] 68 bb [2] 73 bd [2] 6f ba [2] 73 95 }

  condition:
    any of them
}