rule TTP_XOR_QUAD_CurrentVersionRun_5b7b {
  strings:
    $key_5b7b = { 08 14 [2] 2c 1a [2] 07 36 [2] 29 14 [2] 3d 0f [2] 32 15 [2] 2c 08 [2] 2e 09 [2] 35 0f [2] 29 08 [2] 35 27 }

  condition:
    any of them
}