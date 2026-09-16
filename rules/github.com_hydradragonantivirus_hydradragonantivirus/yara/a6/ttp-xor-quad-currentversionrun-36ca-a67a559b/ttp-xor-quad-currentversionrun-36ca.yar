rule TTP_XOR_QUAD_CurrentVersionRun_36ca {
  strings:
    $key_36ca = { 65 a5 [2] 41 ab [2] 6a 87 [2] 44 a5 [2] 50 be [2] 5f a4 [2] 41 b9 [2] 43 b8 [2] 58 be [2] 44 b9 [2] 58 96 }

  condition:
    any of them
}