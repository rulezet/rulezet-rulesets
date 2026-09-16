rule TTP_XOR_QUAD_CurrentVersionRun_5b66 {
  strings:
    $key_5b66 = { 08 09 [2] 2c 07 [2] 07 2b [2] 29 09 [2] 3d 12 [2] 32 08 [2] 2c 15 [2] 2e 14 [2] 35 12 [2] 29 15 [2] 35 3a }

  condition:
    any of them
}