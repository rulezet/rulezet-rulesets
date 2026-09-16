rule TTP_XOR_QUAD_CurrentVersionRun_4df5 {
  strings:
    $key_4df5 = { 1e 9a [2] 3a 94 [2] 11 b8 [2] 3f 9a [2] 2b 81 [2] 24 9b [2] 3a 86 [2] 38 87 [2] 23 81 [2] 3f 86 [2] 23 a9 }

  condition:
    any of them
}