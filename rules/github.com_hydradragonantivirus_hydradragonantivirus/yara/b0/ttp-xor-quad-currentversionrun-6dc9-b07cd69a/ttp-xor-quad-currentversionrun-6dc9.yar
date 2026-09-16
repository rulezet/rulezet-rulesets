rule TTP_XOR_QUAD_CurrentVersionRun_6dc9 {
  strings:
    $key_6dc9 = { 3e a6 [2] 1a a8 [2] 31 84 [2] 1f a6 [2] 0b bd [2] 04 a7 [2] 1a ba [2] 18 bb [2] 03 bd [2] 1f ba [2] 03 95 }

  condition:
    any of them
}