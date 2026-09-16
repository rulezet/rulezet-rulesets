rule TTP_XOR_QUAD_CurrentVersionRun_2561 {
  strings:
    $key_2561 = { 76 0e [2] 52 00 [2] 79 2c [2] 57 0e [2] 43 15 [2] 4c 0f [2] 52 12 [2] 50 13 [2] 4b 15 [2] 57 12 [2] 4b 3d }

  condition:
    any of them
}