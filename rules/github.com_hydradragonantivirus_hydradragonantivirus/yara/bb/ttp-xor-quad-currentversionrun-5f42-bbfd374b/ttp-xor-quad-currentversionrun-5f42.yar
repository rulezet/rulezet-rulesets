rule TTP_XOR_QUAD_CurrentVersionRun_5f42 {
  strings:
    $key_5f42 = { 0c 2d [2] 28 23 [2] 03 0f [2] 2d 2d [2] 39 36 [2] 36 2c [2] 28 31 [2] 2a 30 [2] 31 36 [2] 2d 31 [2] 31 1e }

  condition:
    any of them
}