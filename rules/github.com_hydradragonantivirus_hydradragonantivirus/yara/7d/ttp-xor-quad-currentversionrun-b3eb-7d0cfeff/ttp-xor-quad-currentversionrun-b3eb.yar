rule TTP_XOR_QUAD_CurrentVersionRun_b3eb {
  strings:
    $key_b3eb = { e0 84 [2] c4 8a [2] ef a6 [2] c1 84 [2] d5 9f [2] da 85 [2] c4 98 [2] c6 99 [2] dd 9f [2] c1 98 [2] dd b7 }

  condition:
    any of them
}