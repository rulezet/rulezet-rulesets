rule TTP_XOR_QUAD_CurrentVersionRun_5b67 {
  strings:
    $key_5b67 = { 08 08 [2] 2c 06 [2] 07 2a [2] 29 08 [2] 3d 13 [2] 32 09 [2] 2c 14 [2] 2e 15 [2] 35 13 [2] 29 14 [2] 35 3b }

  condition:
    any of them
}