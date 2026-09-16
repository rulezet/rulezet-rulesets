rule TTP_XOR_QUAD_CurrentVersionRun_4f61 {
  strings:
    $key_4f61 = { 1c 0e [2] 38 00 [2] 13 2c [2] 3d 0e [2] 29 15 [2] 26 0f [2] 38 12 [2] 3a 13 [2] 21 15 [2] 3d 12 [2] 21 3d }

  condition:
    any of them
}