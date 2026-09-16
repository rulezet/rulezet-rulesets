rule TTP_XOR_QUAD_CurrentVersionRun_2361 {
  strings:
    $key_2361 = { 70 0e [2] 54 00 [2] 7f 2c [2] 51 0e [2] 45 15 [2] 4a 0f [2] 54 12 [2] 56 13 [2] 4d 15 [2] 51 12 [2] 4d 3d }

  condition:
    any of them
}