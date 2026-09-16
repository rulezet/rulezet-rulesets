rule TTP_XOR_QUAD_CurrentVersionRun_5b0b {
  strings:
    $key_5b0b = { 08 64 [2] 2c 6a [2] 07 46 [2] 29 64 [2] 3d 7f [2] 32 65 [2] 2c 78 [2] 2e 79 [2] 35 7f [2] 29 78 [2] 35 57 }

  condition:
    any of them
}