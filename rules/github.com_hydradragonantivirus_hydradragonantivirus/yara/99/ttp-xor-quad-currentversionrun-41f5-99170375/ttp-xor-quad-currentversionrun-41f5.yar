rule TTP_XOR_QUAD_CurrentVersionRun_41f5 {
  strings:
    $key_41f5 = { 12 9a [2] 36 94 [2] 1d b8 [2] 33 9a [2] 27 81 [2] 28 9b [2] 36 86 [2] 34 87 [2] 2f 81 [2] 33 86 [2] 2f a9 }

  condition:
    any of them
}