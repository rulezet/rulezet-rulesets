rule TTP_XOR_QUAD_CurrentVersionRun_1f61 {
  strings:
    $key_1f61 = { 4c 0e [2] 68 00 [2] 43 2c [2] 6d 0e [2] 79 15 [2] 76 0f [2] 68 12 [2] 6a 13 [2] 71 15 [2] 6d 12 [2] 71 3d }

  condition:
    any of them
}