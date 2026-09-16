rule TTP_XOR_QUAD_CurrentVersionRun_4761 {
  strings:
    $key_4761 = { 14 0e [2] 30 00 [2] 1b 2c [2] 35 0e [2] 21 15 [2] 2e 0f [2] 30 12 [2] 32 13 [2] 29 15 [2] 35 12 [2] 29 3d }

  condition:
    any of them
}