rule TTP_XOR_QUAD_CurrentVersionRun_5e61 {
  strings:
    $key_5e61 = { 0d 0e [2] 29 00 [2] 02 2c [2] 2c 0e [2] 38 15 [2] 37 0f [2] 29 12 [2] 2b 13 [2] 30 15 [2] 2c 12 [2] 30 3d }

  condition:
    any of them
}