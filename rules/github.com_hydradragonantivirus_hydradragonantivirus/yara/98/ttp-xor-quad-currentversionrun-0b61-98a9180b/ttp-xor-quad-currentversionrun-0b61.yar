rule TTP_XOR_QUAD_CurrentVersionRun_0b61 {
  strings:
    $key_0b61 = { 58 0e [2] 7c 00 [2] 57 2c [2] 79 0e [2] 6d 15 [2] 62 0f [2] 7c 12 [2] 7e 13 [2] 65 15 [2] 79 12 [2] 65 3d }

  condition:
    any of them
}