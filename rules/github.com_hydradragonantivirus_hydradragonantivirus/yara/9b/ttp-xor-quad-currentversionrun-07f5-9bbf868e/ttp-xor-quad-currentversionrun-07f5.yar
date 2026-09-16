rule TTP_XOR_QUAD_CurrentVersionRun_07f5 {
  strings:
    $key_07f5 = { 54 9a [2] 70 94 [2] 5b b8 [2] 75 9a [2] 61 81 [2] 6e 9b [2] 70 86 [2] 72 87 [2] 69 81 [2] 75 86 [2] 69 a9 }

  condition:
    any of them
}