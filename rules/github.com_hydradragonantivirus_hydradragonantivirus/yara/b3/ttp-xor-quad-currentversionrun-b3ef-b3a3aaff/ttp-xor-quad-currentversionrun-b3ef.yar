rule TTP_XOR_QUAD_CurrentVersionRun_b3ef {
  strings:
    $key_b3ef = { e0 80 [2] c4 8e [2] ef a2 [2] c1 80 [2] d5 9b [2] da 81 [2] c4 9c [2] c6 9d [2] dd 9b [2] c1 9c [2] dd b3 }

  condition:
    any of them
}