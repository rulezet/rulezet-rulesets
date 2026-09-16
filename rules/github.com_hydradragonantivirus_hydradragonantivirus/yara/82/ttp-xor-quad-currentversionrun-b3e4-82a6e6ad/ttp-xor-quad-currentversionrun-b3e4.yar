rule TTP_XOR_QUAD_CurrentVersionRun_b3e4 {
  strings:
    $key_b3e4 = { e0 8b [2] c4 85 [2] ef a9 [2] c1 8b [2] d5 90 [2] da 8a [2] c4 97 [2] c6 96 [2] dd 90 [2] c1 97 [2] dd b8 }

  condition:
    any of them
}