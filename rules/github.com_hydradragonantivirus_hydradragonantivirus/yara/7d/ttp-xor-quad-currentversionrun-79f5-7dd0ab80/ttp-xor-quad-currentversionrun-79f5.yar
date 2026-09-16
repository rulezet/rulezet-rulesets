rule TTP_XOR_QUAD_CurrentVersionRun_79f5 {
  strings:
    $key_79f5 = { 2a 9a [2] 0e 94 [2] 25 b8 [2] 0b 9a [2] 1f 81 [2] 10 9b [2] 0e 86 [2] 0c 87 [2] 17 81 [2] 0b 86 [2] 17 a9 }

  condition:
    any of them
}