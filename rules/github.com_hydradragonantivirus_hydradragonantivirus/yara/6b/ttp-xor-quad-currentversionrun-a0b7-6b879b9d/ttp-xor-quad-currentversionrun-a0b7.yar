rule TTP_XOR_QUAD_CurrentVersionRun_a0b7 {
  strings:
    $key_a0b7 = { f3 d8 [2] d7 d6 [2] fc fa [2] d2 d8 [2] c6 c3 [2] c9 d9 [2] d7 c4 [2] d5 c5 [2] ce c3 [2] d2 c4 [2] ce eb }

  condition:
    any of them
}