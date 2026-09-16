rule TTP_XOR_QUAD_CurrentVersionRun_b368 {
  strings:
    $key_b368 = { e0 07 [2] c4 09 [2] ef 25 [2] c1 07 [2] d5 1c [2] da 06 [2] c4 1b [2] c6 1a [2] dd 1c [2] c1 1b [2] dd 34 }

  condition:
    any of them
}