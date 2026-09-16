rule TTP_XOR_QUAD_CurrentVersionRun_3b61 {
  strings:
    $key_3b61 = { 68 0e [2] 4c 00 [2] 67 2c [2] 49 0e [2] 5d 15 [2] 52 0f [2] 4c 12 [2] 4e 13 [2] 55 15 [2] 49 12 [2] 55 3d }

  condition:
    any of them
}