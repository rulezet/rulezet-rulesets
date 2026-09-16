rule TTP_XOR_QUAD_CurrentVersionRun_47f5 {
  strings:
    $key_47f5 = { 14 9a [2] 30 94 [2] 1b b8 [2] 35 9a [2] 21 81 [2] 2e 9b [2] 30 86 [2] 32 87 [2] 29 81 [2] 35 86 [2] 29 a9 }

  condition:
    any of them
}