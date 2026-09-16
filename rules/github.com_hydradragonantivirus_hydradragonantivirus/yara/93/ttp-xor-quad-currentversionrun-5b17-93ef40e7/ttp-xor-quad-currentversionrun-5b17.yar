rule TTP_XOR_QUAD_CurrentVersionRun_5b17 {
  strings:
    $key_5b17 = { 08 78 [2] 2c 76 [2] 07 5a [2] 29 78 [2] 3d 63 [2] 32 79 [2] 2c 64 [2] 2e 65 [2] 35 63 [2] 29 64 [2] 35 4b }

  condition:
    any of them
}