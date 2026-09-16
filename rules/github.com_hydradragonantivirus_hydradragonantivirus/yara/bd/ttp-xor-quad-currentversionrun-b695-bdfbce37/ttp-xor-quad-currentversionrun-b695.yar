rule TTP_XOR_QUAD_CurrentVersionRun_b695 {
  strings:
    $key_b695 = { e5 fa [2] c1 f4 [2] ea d8 [2] c4 fa [2] d0 e1 [2] df fb [2] c1 e6 [2] c3 e7 [2] d8 e1 [2] c4 e6 [2] d8 c9 }

  condition:
    any of them
}