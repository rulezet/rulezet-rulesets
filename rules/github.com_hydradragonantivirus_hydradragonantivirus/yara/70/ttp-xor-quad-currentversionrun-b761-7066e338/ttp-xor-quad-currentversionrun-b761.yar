rule TTP_XOR_QUAD_CurrentVersionRun_b761 {
  strings:
    $key_b761 = { e4 0e [2] c0 00 [2] eb 2c [2] c5 0e [2] d1 15 [2] de 0f [2] c0 12 [2] c2 13 [2] d9 15 [2] c5 12 [2] d9 3d }

  condition:
    any of them
}