rule TTP_XOR_QUAD_CurrentVersionRun_1f42 {
  strings:
    $key_1f42 = { 4c 2d [2] 68 23 [2] 43 0f [2] 6d 2d [2] 79 36 [2] 76 2c [2] 68 31 [2] 6a 30 [2] 71 36 [2] 6d 31 [2] 71 1e }

  condition:
    any of them
}