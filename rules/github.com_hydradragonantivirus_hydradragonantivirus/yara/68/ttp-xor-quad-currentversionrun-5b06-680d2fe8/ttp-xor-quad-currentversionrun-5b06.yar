rule TTP_XOR_QUAD_CurrentVersionRun_5b06 {
  strings:
    $key_5b06 = { 08 69 [2] 2c 67 [2] 07 4b [2] 29 69 [2] 3d 72 [2] 32 68 [2] 2c 75 [2] 2e 74 [2] 35 72 [2] 29 75 [2] 35 5a }

  condition:
    any of them
}