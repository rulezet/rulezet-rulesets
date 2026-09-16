rule TTP_XOR_QUAD_CurrentVersionRun_6661 {
  strings:
    $key_6661 = { 35 0e [2] 11 00 [2] 3a 2c [2] 14 0e [2] 00 15 [2] 0f 0f [2] 11 12 [2] 13 13 [2] 08 15 [2] 14 12 [2] 08 3d }

  condition:
    any of them
}