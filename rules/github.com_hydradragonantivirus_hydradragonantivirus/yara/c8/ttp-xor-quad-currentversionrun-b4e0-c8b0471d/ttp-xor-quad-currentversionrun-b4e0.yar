rule TTP_XOR_QUAD_CurrentVersionRun_b4e0 {
  strings:
    $key_b4e0 = { e7 8f [2] c3 81 [2] e8 ad [2] c6 8f [2] d2 94 [2] dd 8e [2] c3 93 [2] c1 92 [2] da 94 [2] c6 93 [2] da bc }

  condition:
    any of them
}