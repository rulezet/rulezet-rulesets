rule TTP_XOR_QUAD_CurrentVersionRun_5b46 {
  strings:
    $key_5b46 = { 08 29 [2] 2c 27 [2] 07 0b [2] 29 29 [2] 3d 32 [2] 32 28 [2] 2c 35 [2] 2e 34 [2] 35 32 [2] 29 35 [2] 35 1a }

  condition:
    any of them
}