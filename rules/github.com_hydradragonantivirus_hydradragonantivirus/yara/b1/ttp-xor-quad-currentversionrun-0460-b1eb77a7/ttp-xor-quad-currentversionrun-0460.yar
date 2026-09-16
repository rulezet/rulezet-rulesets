rule TTP_XOR_QUAD_CurrentVersionRun_0460 {
  strings:
    $key_0460 = { 57 0f [2] 73 01 [2] 58 2d [2] 76 0f [2] 62 14 [2] 6d 0e [2] 73 13 [2] 71 12 [2] 6a 14 [2] 76 13 [2] 6a 3c }

  condition:
    any of them
}