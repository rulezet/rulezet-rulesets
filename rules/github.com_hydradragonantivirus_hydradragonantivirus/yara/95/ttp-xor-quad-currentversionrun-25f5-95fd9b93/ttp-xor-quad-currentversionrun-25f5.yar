rule TTP_XOR_QUAD_CurrentVersionRun_25f5 {
  strings:
    $key_25f5 = { 76 9a [2] 52 94 [2] 79 b8 [2] 57 9a [2] 43 81 [2] 4c 9b [2] 52 86 [2] 50 87 [2] 4b 81 [2] 57 86 [2] 4b a9 }

  condition:
    any of them
}