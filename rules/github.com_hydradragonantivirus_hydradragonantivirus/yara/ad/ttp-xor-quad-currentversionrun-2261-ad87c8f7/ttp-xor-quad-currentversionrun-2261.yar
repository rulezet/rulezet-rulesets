rule TTP_XOR_QUAD_CurrentVersionRun_2261 {
  strings:
    $key_2261 = { 71 0e [2] 55 00 [2] 7e 2c [2] 50 0e [2] 44 15 [2] 4b 0f [2] 55 12 [2] 57 13 [2] 4c 15 [2] 50 12 [2] 4c 3d }

  condition:
    any of them
}