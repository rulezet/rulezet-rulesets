rule TTP_XOR_QUAD_CurrentVersionRun_5be9 {
  strings:
    $key_5be9 = { 08 86 [2] 2c 88 [2] 07 a4 [2] 29 86 [2] 3d 9d [2] 32 87 [2] 2c 9a [2] 2e 9b [2] 35 9d [2] 29 9a [2] 35 b5 }

  condition:
    any of them
}