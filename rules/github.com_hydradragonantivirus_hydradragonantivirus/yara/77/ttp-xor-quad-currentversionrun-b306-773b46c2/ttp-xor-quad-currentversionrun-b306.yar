rule TTP_XOR_QUAD_CurrentVersionRun_b306 {
  strings:
    $key_b306 = { e0 69 [2] c4 67 [2] ef 4b [2] c1 69 [2] d5 72 [2] da 68 [2] c4 75 [2] c6 74 [2] dd 72 [2] c1 75 [2] dd 5a }

  condition:
    any of them
}