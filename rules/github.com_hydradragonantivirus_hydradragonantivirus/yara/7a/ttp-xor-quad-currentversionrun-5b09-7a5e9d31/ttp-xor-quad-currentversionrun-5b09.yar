rule TTP_XOR_QUAD_CurrentVersionRun_5b09 {
  strings:
    $key_5b09 = { 08 66 [2] 2c 68 [2] 07 44 [2] 29 66 [2] 3d 7d [2] 32 67 [2] 2c 7a [2] 2e 7b [2] 35 7d [2] 29 7a [2] 35 55 }

  condition:
    any of them
}