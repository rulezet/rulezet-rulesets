rule TTP_XOR_QUAD_CurrentVersionRun_67f5 {
  strings:
    $key_67f5 = { 34 9a [2] 10 94 [2] 3b b8 [2] 15 9a [2] 01 81 [2] 0e 9b [2] 10 86 [2] 12 87 [2] 09 81 [2] 15 86 [2] 09 a9 }

  condition:
    any of them
}