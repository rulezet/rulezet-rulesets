rule TTP_XOR_QUAD_CurrentVersionRun_68ca {
  strings:
    $key_68ca = { 3b a5 [2] 1f ab [2] 34 87 [2] 1a a5 [2] 0e be [2] 01 a4 [2] 1f b9 [2] 1d b8 [2] 06 be [2] 1a b9 [2] 06 96 }

  condition:
    any of them
}