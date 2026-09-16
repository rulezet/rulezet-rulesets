rule TTP_XOR_QUAD_CurrentVersionRun_5f61 {
  strings:
    $key_5f61 = { 0c 0e [2] 28 00 [2] 03 2c [2] 2d 0e [2] 39 15 [2] 36 0f [2] 28 12 [2] 2a 13 [2] 31 15 [2] 2d 12 [2] 31 3d }

  condition:
    any of them
}