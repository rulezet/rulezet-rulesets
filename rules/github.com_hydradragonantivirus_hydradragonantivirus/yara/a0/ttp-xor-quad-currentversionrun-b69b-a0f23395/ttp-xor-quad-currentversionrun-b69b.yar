rule TTP_XOR_QUAD_CurrentVersionRun_b69b {
  strings:
    $key_b69b = { e5 f4 [2] c1 fa [2] ea d6 [2] c4 f4 [2] d0 ef [2] df f5 [2] c1 e8 [2] c3 e9 [2] d8 ef [2] c4 e8 [2] d8 c7 }

  condition:
    any of them
}