rule TTP_XOR_QUAD_CurrentVersionRun_b3f0 {
  strings:
    $key_b3f0 = { e0 9f [2] c4 91 [2] ef bd [2] c1 9f [2] d5 84 [2] da 9e [2] c4 83 [2] c6 82 [2] dd 84 [2] c1 83 [2] dd ac }

  condition:
    any of them
}