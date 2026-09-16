rule TTP_XOR_QUAD_CurrentVersionRun_b4f6 {
  strings:
    $key_b4f6 = { e7 99 [2] c3 97 [2] e8 bb [2] c6 99 [2] d2 82 [2] dd 98 [2] c3 85 [2] c1 84 [2] da 82 [2] c6 85 [2] da aa }

  condition:
    any of them
}