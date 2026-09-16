rule TTP_XOR_QUAD_CurrentVersionRun_58ca {
  strings:
    $key_58ca = { 0b a5 [2] 2f ab [2] 04 87 [2] 2a a5 [2] 3e be [2] 31 a4 [2] 2f b9 [2] 2d b8 [2] 36 be [2] 2a b9 [2] 36 96 }

  condition:
    any of them
}