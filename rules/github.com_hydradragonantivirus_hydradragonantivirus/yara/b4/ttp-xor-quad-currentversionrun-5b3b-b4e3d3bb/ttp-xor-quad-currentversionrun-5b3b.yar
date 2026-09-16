rule TTP_XOR_QUAD_CurrentVersionRun_5b3b {
  strings:
    $key_5b3b = { 08 54 [2] 2c 5a [2] 07 76 [2] 29 54 [2] 3d 4f [2] 32 55 [2] 2c 48 [2] 2e 49 [2] 35 4f [2] 29 48 [2] 35 67 }

  condition:
    any of them
}