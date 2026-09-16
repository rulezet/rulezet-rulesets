rule TTP_XOR_QUAD_CurrentVersionRun_5b1b {
  strings:
    $key_5b1b = { 08 74 [2] 2c 7a [2] 07 56 [2] 29 74 [2] 3d 6f [2] 32 75 [2] 2c 68 [2] 2e 69 [2] 35 6f [2] 29 68 [2] 35 47 }

  condition:
    any of them
}