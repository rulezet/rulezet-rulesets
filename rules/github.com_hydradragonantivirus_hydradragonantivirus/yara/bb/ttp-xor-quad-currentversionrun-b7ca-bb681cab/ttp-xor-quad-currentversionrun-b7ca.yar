rule TTP_XOR_QUAD_CurrentVersionRun_b7ca {
  strings:
    $key_b7ca = { e4 a5 [2] c0 ab [2] eb 87 [2] c5 a5 [2] d1 be [2] de a4 [2] c0 b9 [2] c2 b8 [2] d9 be [2] c5 b9 [2] d9 96 }

  condition:
    any of them
}