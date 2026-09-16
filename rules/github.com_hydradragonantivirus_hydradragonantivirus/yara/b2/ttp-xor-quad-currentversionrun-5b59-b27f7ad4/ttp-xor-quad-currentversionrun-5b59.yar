rule TTP_XOR_QUAD_CurrentVersionRun_5b59 {
  strings:
    $key_5b59 = { 08 36 [2] 2c 38 [2] 07 14 [2] 29 36 [2] 3d 2d [2] 32 37 [2] 2c 2a [2] 2e 2b [2] 35 2d [2] 29 2a [2] 35 05 }

  condition:
    any of them
}