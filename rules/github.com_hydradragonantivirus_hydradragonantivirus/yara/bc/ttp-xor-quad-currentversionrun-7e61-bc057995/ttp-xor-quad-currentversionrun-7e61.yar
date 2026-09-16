rule TTP_XOR_QUAD_CurrentVersionRun_7e61 {
  strings:
    $key_7e61 = { 2d 0e [2] 09 00 [2] 22 2c [2] 0c 0e [2] 18 15 [2] 17 0f [2] 09 12 [2] 0b 13 [2] 10 15 [2] 0c 12 [2] 10 3d }

  condition:
    any of them
}