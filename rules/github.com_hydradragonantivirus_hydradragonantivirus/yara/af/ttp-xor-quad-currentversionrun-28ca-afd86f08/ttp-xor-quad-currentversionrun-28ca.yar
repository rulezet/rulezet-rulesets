rule TTP_XOR_QUAD_CurrentVersionRun_28ca {
  strings:
    $key_28ca = { 7b a5 [2] 5f ab [2] 74 87 [2] 5a a5 [2] 4e be [2] 41 a4 [2] 5f b9 [2] 5d b8 [2] 46 be [2] 5a b9 [2] 46 96 }

  condition:
    any of them
}