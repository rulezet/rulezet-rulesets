rule TTP_XOR_QUAD_CurrentVersionRun_46ca {
  strings:
    $key_46ca = { 15 a5 [2] 31 ab [2] 1a 87 [2] 34 a5 [2] 20 be [2] 2f a4 [2] 31 b9 [2] 33 b8 [2] 28 be [2] 34 b9 [2] 28 96 }

  condition:
    any of them
}