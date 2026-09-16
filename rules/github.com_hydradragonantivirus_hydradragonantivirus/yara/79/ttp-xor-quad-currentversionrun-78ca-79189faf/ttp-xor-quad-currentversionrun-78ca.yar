rule TTP_XOR_QUAD_CurrentVersionRun_78ca {
  strings:
    $key_78ca = { 2b a5 [2] 0f ab [2] 24 87 [2] 0a a5 [2] 1e be [2] 11 a4 [2] 0f b9 [2] 0d b8 [2] 16 be [2] 0a b9 [2] 16 96 }

  condition:
    any of them
}