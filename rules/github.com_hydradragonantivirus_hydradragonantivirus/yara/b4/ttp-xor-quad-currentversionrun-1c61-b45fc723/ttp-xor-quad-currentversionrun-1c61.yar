rule TTP_XOR_QUAD_CurrentVersionRun_1c61 {
  strings:
    $key_1c61 = { 4f 0e [2] 6b 00 [2] 40 2c [2] 6e 0e [2] 7a 15 [2] 75 0f [2] 6b 12 [2] 69 13 [2] 72 15 [2] 6e 12 [2] 72 3d }

  condition:
    any of them
}