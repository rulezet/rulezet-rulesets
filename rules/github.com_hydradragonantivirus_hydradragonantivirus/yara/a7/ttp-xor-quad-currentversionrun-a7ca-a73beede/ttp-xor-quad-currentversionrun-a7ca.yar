rule TTP_XOR_QUAD_CurrentVersionRun_a7ca {
  strings:
    $key_a7ca = { f4 a5 [2] d0 ab [2] fb 87 [2] d5 a5 [2] c1 be [2] ce a4 [2] d0 b9 [2] d2 b8 [2] c9 be [2] d5 b9 [2] c9 96 }

  condition:
    any of them
}