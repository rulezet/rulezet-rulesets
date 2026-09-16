rule TTP_XOR_QUAD_CurrentVersionRun_2f61 {
  strings:
    $key_2f61 = { 7c 0e [2] 58 00 [2] 73 2c [2] 5d 0e [2] 49 15 [2] 46 0f [2] 58 12 [2] 5a 13 [2] 41 15 [2] 5d 12 [2] 41 3d }

  condition:
    any of them
}