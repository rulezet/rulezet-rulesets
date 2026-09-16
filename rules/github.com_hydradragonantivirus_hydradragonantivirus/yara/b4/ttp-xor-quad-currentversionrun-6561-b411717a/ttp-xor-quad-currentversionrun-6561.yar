rule TTP_XOR_QUAD_CurrentVersionRun_6561 {
  strings:
    $key_6561 = { 36 0e [2] 12 00 [2] 39 2c [2] 17 0e [2] 03 15 [2] 0c 0f [2] 12 12 [2] 10 13 [2] 0b 15 [2] 17 12 [2] 0b 3d }

  condition:
    any of them
}