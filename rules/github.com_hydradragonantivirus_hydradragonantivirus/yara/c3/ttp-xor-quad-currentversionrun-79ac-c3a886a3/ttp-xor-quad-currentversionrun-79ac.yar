rule TTP_XOR_QUAD_CurrentVersionRun_79ac {
  strings:
    $key_79ac = { 2a c3 [2] 0e cd [2] 25 e1 [2] 0b c3 [2] 1f d8 [2] 10 c2 [2] 0e df [2] 0c de [2] 17 d8 [2] 0b df [2] 17 f0 }

  condition:
    any of them
}