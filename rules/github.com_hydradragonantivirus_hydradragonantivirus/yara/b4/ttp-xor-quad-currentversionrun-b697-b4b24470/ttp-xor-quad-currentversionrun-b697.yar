rule TTP_XOR_QUAD_CurrentVersionRun_b697 {
  strings:
    $key_b697 = { e5 f8 [2] c1 f6 [2] ea da [2] c4 f8 [2] d0 e3 [2] df f9 [2] c1 e4 [2] c3 e5 [2] d8 e3 [2] c4 e4 [2] d8 cb }

  condition:
    any of them
}