rule TTP_XOR_QUAD_CurrentVersionRun_b346 {
  strings:
    $key_b346 = { e0 29 [2] c4 27 [2] ef 0b [2] c1 29 [2] d5 32 [2] da 28 [2] c4 35 [2] c6 34 [2] dd 32 [2] c1 35 [2] dd 1a }

  condition:
    any of them
}