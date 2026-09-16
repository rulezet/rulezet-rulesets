rule TTP_XOR_QUAD_CurrentVersionRun_4c61 {
  strings:
    $key_4c61 = { 1f 0e [2] 3b 00 [2] 10 2c [2] 3e 0e [2] 2a 15 [2] 25 0f [2] 3b 12 [2] 39 13 [2] 22 15 [2] 3e 12 [2] 22 3d }

  condition:
    any of them
}