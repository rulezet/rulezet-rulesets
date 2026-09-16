rule TTP_XOR_QUAD_CurrentVersionRun_18ca {
  strings:
    $key_18ca = { 4b a5 [2] 6f ab [2] 44 87 [2] 6a a5 [2] 7e be [2] 71 a4 [2] 6f b9 [2] 6d b8 [2] 76 be [2] 6a b9 [2] 76 96 }

  condition:
    any of them
}