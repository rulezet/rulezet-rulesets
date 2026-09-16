rule TTP_XOR_QUAD_CurrentVersionRun_0442 {
  strings:
    $key_0442 = { 57 2d [2] 73 23 [2] 58 0f [2] 76 2d [2] 62 36 [2] 6d 2c [2] 73 31 [2] 71 30 [2] 6a 36 [2] 76 31 [2] 6a 1e }

  condition:
    any of them
}