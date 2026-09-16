rule TTP_XOR_QUAD_CurrentVersionRun_a3ca {
  strings:
    $key_a3ca = { f0 a5 [2] d4 ab [2] ff 87 [2] d1 a5 [2] c5 be [2] ca a4 [2] d4 b9 [2] d6 b8 [2] cd be [2] d1 b9 [2] cd 96 }

  condition:
    any of them
}