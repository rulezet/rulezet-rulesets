rule TTP_XOR_QUAD_CurrentVersionRun_b6ca {
  strings:
    $key_b6ca = { e5 a5 [2] c1 ab [2] ea 87 [2] c4 a5 [2] d0 be [2] df a4 [2] c1 b9 [2] c3 b8 [2] d8 be [2] c4 b9 [2] d8 96 }

  condition:
    any of them
}