rule TTP_XOR_QUAD_CurrentVersionRun_6042 {
  strings:
    $key_6042 = { 33 2d [2] 17 23 [2] 3c 0f [2] 12 2d [2] 06 36 [2] 09 2c [2] 17 31 [2] 15 30 [2] 0e 36 [2] 12 31 [2] 0e 1e }

  condition:
    any of them
}