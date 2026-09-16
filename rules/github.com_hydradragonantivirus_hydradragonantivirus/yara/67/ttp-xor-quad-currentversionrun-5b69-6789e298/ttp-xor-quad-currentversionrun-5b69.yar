rule TTP_XOR_QUAD_CurrentVersionRun_5b69 {
  strings:
    $key_5b69 = { 08 06 [2] 2c 08 [2] 07 24 [2] 29 06 [2] 3d 1d [2] 32 07 [2] 2c 1a [2] 2e 1b [2] 35 1d [2] 29 1a [2] 35 35 }

  condition:
    any of them
}