rule TTP_XOR_QUAD_CurrentVersionRun_5ef5 {
  strings:
    $key_5ef5 = { 0d 9a [2] 29 94 [2] 02 b8 [2] 2c 9a [2] 38 81 [2] 37 9b [2] 29 86 [2] 2b 87 [2] 30 81 [2] 2c 86 [2] 30 a9 }

  condition:
    any of them
}