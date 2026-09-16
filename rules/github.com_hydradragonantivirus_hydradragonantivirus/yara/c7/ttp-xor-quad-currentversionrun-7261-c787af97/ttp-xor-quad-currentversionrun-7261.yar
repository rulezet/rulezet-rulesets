rule TTP_XOR_QUAD_CurrentVersionRun_7261 {
  strings:
    $key_7261 = { 21 0e [2] 05 00 [2] 2e 2c [2] 00 0e [2] 14 15 [2] 1b 0f [2] 05 12 [2] 07 13 [2] 1c 15 [2] 00 12 [2] 1c 3d }

  condition:
    any of them
}