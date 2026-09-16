rule TTP_XOR_QUAD_CurrentVersionRun_5761 {
  strings:
    $key_5761 = { 04 0e [2] 20 00 [2] 0b 2c [2] 25 0e [2] 31 15 [2] 3e 0f [2] 20 12 [2] 22 13 [2] 39 15 [2] 25 12 [2] 39 3d }

  condition:
    any of them
}