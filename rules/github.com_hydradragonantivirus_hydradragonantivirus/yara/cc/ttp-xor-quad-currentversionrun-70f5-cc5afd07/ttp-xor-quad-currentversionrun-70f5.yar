rule TTP_XOR_QUAD_CurrentVersionRun_70f5 {
  strings:
    $key_70f5 = { 23 9a [2] 07 94 [2] 2c b8 [2] 02 9a [2] 16 81 [2] 19 9b [2] 07 86 [2] 05 87 [2] 1e 81 [2] 02 86 [2] 1e a9 }

  condition:
    any of them
}