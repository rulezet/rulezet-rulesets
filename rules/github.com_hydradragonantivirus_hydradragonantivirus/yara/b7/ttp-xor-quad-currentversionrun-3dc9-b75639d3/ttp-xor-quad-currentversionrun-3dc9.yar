rule TTP_XOR_QUAD_CurrentVersionRun_3dc9 {
  strings:
    $key_3dc9 = { 6e a6 [2] 4a a8 [2] 61 84 [2] 4f a6 [2] 5b bd [2] 54 a7 [2] 4a ba [2] 48 bb [2] 53 bd [2] 4f ba [2] 53 95 }

  condition:
    any of them
}