rule TTP_XOR_QUAD_CurrentVersionRun_1561 {
  strings:
    $key_1561 = { 46 0e [2] 62 00 [2] 49 2c [2] 67 0e [2] 73 15 [2] 7c 0f [2] 62 12 [2] 60 13 [2] 7b 15 [2] 67 12 [2] 7b 3d }

  condition:
    any of them
}