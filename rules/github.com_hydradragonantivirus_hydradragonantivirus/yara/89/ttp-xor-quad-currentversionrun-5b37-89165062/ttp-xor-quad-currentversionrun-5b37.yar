rule TTP_XOR_QUAD_CurrentVersionRun_5b37 {
  strings:
    $key_5b37 = { 08 58 [2] 2c 56 [2] 07 7a [2] 29 58 [2] 3d 43 [2] 32 59 [2] 2c 44 [2] 2e 45 [2] 35 43 [2] 29 44 [2] 35 6b }

  condition:
    any of them
}