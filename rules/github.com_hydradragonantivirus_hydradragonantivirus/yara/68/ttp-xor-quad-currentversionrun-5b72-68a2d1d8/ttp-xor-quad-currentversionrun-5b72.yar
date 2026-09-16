rule TTP_XOR_QUAD_CurrentVersionRun_5b72 {
  strings:
    $key_5b72 = { 08 1d [2] 2c 13 [2] 07 3f [2] 29 1d [2] 3d 06 [2] 32 1c [2] 2c 01 [2] 2e 00 [2] 35 06 [2] 29 01 [2] 35 2e }

  condition:
    any of them
}