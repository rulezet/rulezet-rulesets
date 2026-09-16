rule TTP_XOR_QUAD_CurrentVersionRun_b356 {
  strings:
    $key_b356 = { e0 39 [2] c4 37 [2] ef 1b [2] c1 39 [2] d5 22 [2] da 38 [2] c4 25 [2] c6 24 [2] dd 22 [2] c1 25 [2] dd 0a }

  condition:
    any of them
}