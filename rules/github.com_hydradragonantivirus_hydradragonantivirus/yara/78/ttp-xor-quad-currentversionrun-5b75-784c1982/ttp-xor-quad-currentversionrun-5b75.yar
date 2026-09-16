rule TTP_XOR_QUAD_CurrentVersionRun_5b75 {
  strings:
    $key_5b75 = { 08 1a [2] 2c 14 [2] 07 38 [2] 29 1a [2] 3d 01 [2] 32 1b [2] 2c 06 [2] 2e 07 [2] 35 01 [2] 29 06 [2] 35 29 }

  condition:
    any of them
}