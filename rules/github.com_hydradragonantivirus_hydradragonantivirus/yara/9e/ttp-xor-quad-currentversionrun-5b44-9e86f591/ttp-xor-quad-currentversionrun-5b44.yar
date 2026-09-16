rule TTP_XOR_QUAD_CurrentVersionRun_5b44 {
  strings:
    $key_5b44 = { 08 2b [2] 2c 25 [2] 07 09 [2] 29 2b [2] 3d 30 [2] 32 2a [2] 2c 37 [2] 2e 36 [2] 35 30 [2] 29 37 [2] 35 18 }

  condition:
    any of them
}