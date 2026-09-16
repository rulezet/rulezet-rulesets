rule TTP_XOR_QUAD_CurrentVersionRun_3361 {
  strings:
    $key_3361 = { 60 0e [2] 44 00 [2] 6f 2c [2] 41 0e [2] 55 15 [2] 5a 0f [2] 44 12 [2] 46 13 [2] 5d 15 [2] 41 12 [2] 5d 3d }

  condition:
    any of them
}