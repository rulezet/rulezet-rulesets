rule TTP_XOR_QUAD_CurrentVersionRun_5461 {
  strings:
    $key_5461 = { 07 0e [2] 23 00 [2] 08 2c [2] 26 0e [2] 32 15 [2] 3d 0f [2] 23 12 [2] 21 13 [2] 3a 15 [2] 26 12 [2] 3a 3d }

  condition:
    any of them
}