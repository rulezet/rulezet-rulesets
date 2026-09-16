rule TTP_XOR_QUAD_CurrentVersionRun_6061 {
  strings:
    $key_6061 = { 33 0e [2] 17 00 [2] 3c 2c [2] 12 0e [2] 06 15 [2] 09 0f [2] 17 12 [2] 15 13 [2] 0e 15 [2] 12 12 [2] 0e 3d }

  condition:
    any of them
}