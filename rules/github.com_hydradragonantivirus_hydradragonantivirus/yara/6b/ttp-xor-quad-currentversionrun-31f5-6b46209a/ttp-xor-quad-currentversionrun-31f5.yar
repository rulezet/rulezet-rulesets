rule TTP_XOR_QUAD_CurrentVersionRun_31f5 {
  strings:
    $key_31f5 = { 62 9a [2] 46 94 [2] 6d b8 [2] 43 9a [2] 57 81 [2] 58 9b [2] 46 86 [2] 44 87 [2] 5f 81 [2] 43 86 [2] 5f a9 }

  condition:
    any of them
}