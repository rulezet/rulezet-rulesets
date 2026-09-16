rule TTP_XOR_QUAD_CurrentVersionRun_5b73 {
  strings:
    $key_5b73 = { 08 1c [2] 2c 12 [2] 07 3e [2] 29 1c [2] 3d 07 [2] 32 1d [2] 2c 00 [2] 2e 01 [2] 35 07 [2] 29 00 [2] 35 2f }

  condition:
    any of them
}