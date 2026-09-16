rule TTP_XOR_QUAD_CurrentVersionRun_42f5 {
  strings:
    $key_42f5 = { 11 9a [2] 35 94 [2] 1e b8 [2] 30 9a [2] 24 81 [2] 2b 9b [2] 35 86 [2] 37 87 [2] 2c 81 [2] 30 86 [2] 2c a9 }

  condition:
    any of them
}