rule TTP_XOR_QUAD_CurrentVersionRun_a6ca {
  strings:
    $key_a6ca = { f5 a5 [2] d1 ab [2] fa 87 [2] d4 a5 [2] c0 be [2] cf a4 [2] d1 b9 [2] d3 b8 [2] c8 be [2] d4 b9 [2] c8 96 }

  condition:
    any of them
}