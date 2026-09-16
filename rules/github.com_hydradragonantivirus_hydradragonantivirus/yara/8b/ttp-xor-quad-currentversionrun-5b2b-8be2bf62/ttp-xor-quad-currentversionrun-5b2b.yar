rule TTP_XOR_QUAD_CurrentVersionRun_5b2b {
  strings:
    $key_5b2b = { 08 44 [2] 2c 4a [2] 07 66 [2] 29 44 [2] 3d 5f [2] 32 45 [2] 2c 58 [2] 2e 59 [2] 35 5f [2] 29 58 [2] 35 77 }

  condition:
    any of them
}