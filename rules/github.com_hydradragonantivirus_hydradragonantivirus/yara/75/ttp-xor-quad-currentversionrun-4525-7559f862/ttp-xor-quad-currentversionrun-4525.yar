rule TTP_XOR_QUAD_CurrentVersionRun_4525 {
  strings:
    $key_4525 = { 16 4a [2] 32 44 [2] 19 68 [2] 37 4a [2] 23 51 [2] 2c 4b [2] 32 56 [2] 30 57 [2] 2b 51 [2] 37 56 [2] 2b 79 }

  condition:
    any of them
}