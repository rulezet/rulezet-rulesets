rule TTP_XOR_QUAD_CurrentVersionRun_1061 {
  strings:
    $key_1061 = { 43 0e [2] 67 00 [2] 4c 2c [2] 62 0e [2] 76 15 [2] 79 0f [2] 67 12 [2] 65 13 [2] 7e 15 [2] 62 12 [2] 7e 3d }

  condition:
    any of them
}