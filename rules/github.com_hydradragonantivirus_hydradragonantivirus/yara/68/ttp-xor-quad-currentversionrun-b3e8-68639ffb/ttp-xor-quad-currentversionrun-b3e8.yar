rule TTP_XOR_QUAD_CurrentVersionRun_b3e8 {
  strings:
    $key_b3e8 = { e0 87 [2] c4 89 [2] ef a5 [2] c1 87 [2] d5 9c [2] da 86 [2] c4 9b [2] c6 9a [2] dd 9c [2] c1 9b [2] dd b4 }

  condition:
    any of them
}