rule TTP_XOR_QUAD_CurrentVersionRun_5b54 {
  strings:
    $key_5b54 = { 08 3b [2] 2c 35 [2] 07 19 [2] 29 3b [2] 3d 20 [2] 32 3a [2] 2c 27 [2] 2e 26 [2] 35 20 [2] 29 27 [2] 35 08 }

  condition:
    any of them
}