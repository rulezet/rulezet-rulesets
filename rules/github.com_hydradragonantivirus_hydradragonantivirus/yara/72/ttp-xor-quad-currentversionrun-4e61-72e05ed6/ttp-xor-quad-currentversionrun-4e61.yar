rule TTP_XOR_QUAD_CurrentVersionRun_4e61 {
  strings:
    $key_4e61 = { 1d 0e [2] 39 00 [2] 12 2c [2] 3c 0e [2] 28 15 [2] 27 0f [2] 39 12 [2] 3b 13 [2] 20 15 [2] 3c 12 [2] 20 3d }

  condition:
    any of them
}