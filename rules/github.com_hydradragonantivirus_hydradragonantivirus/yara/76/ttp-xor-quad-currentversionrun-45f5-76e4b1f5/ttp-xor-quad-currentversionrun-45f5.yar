rule TTP_XOR_QUAD_CurrentVersionRun_45f5 {
  strings:
    $key_45f5 = { 16 9a [2] 32 94 [2] 19 b8 [2] 37 9a [2] 23 81 [2] 2c 9b [2] 32 86 [2] 30 87 [2] 2b 81 [2] 37 86 [2] 2b a9 }

  condition:
    any of them
}