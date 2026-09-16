rule TTP_XOR_QUAD_CurrentVersionRun_b3ec {
  strings:
    $key_b3ec = { e0 83 [2] c4 8d [2] ef a1 [2] c1 83 [2] d5 98 [2] da 82 [2] c4 9f [2] c6 9e [2] dd 98 [2] c1 9f [2] dd b0 }

  condition:
    any of them
}