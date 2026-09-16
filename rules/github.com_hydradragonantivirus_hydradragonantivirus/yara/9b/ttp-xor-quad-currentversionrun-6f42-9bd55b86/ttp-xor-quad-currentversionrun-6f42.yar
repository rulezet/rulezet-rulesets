rule TTP_XOR_QUAD_CurrentVersionRun_6f42 {
  strings:
    $key_6f42 = { 3c 2d [2] 18 23 [2] 33 0f [2] 1d 2d [2] 09 36 [2] 06 2c [2] 18 31 [2] 1a 30 [2] 01 36 [2] 1d 31 [2] 01 1e }

  condition:
    any of them
}