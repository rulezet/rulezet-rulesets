rule TTP_XOR_QUAD_CurrentVersionRun_5b5b {
  strings:
    $key_5b5b = { 08 34 [2] 2c 3a [2] 07 16 [2] 29 34 [2] 3d 2f [2] 32 35 [2] 2c 28 [2] 2e 29 [2] 35 2f [2] 29 28 [2] 35 07 }

  condition:
    any of them
}