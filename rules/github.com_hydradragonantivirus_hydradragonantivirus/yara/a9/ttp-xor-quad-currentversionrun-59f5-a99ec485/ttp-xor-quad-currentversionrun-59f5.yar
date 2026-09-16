rule TTP_XOR_QUAD_CurrentVersionRun_59f5 {
  strings:
    $key_59f5 = { 0a 9a [2] 2e 94 [2] 05 b8 [2] 2b 9a [2] 3f 81 [2] 30 9b [2] 2e 86 [2] 2c 87 [2] 37 81 [2] 2b 86 [2] 37 a9 }

  condition:
    any of them
}