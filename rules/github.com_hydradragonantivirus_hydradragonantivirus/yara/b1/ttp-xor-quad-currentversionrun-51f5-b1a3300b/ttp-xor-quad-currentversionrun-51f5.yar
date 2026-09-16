rule TTP_XOR_QUAD_CurrentVersionRun_51f5 {
  strings:
    $key_51f5 = { 02 9a [2] 26 94 [2] 0d b8 [2] 23 9a [2] 37 81 [2] 38 9b [2] 26 86 [2] 24 87 [2] 3f 81 [2] 23 86 [2] 3f a9 }

  condition:
    any of them
}