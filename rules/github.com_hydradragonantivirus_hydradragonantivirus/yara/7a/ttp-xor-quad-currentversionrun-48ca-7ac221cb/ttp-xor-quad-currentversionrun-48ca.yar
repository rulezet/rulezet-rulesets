rule TTP_XOR_QUAD_CurrentVersionRun_48ca {
  strings:
    $key_48ca = { 1b a5 [2] 3f ab [2] 14 87 [2] 3a a5 [2] 2e be [2] 21 a4 [2] 3f b9 [2] 3d b8 [2] 26 be [2] 3a b9 [2] 26 96 }

  condition:
    any of them
}