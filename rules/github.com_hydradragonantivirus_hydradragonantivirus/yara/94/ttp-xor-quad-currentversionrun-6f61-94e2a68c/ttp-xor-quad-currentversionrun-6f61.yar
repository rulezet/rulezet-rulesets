rule TTP_XOR_QUAD_CurrentVersionRun_6f61 {
  strings:
    $key_6f61 = { 3c 0e [2] 18 00 [2] 33 2c [2] 1d 0e [2] 09 15 [2] 06 0f [2] 18 12 [2] 1a 13 [2] 01 15 [2] 1d 12 [2] 01 3d }

  condition:
    any of them
}