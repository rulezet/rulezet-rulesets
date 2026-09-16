rule TTP_XOR_QUAD_CurrentVersionRun_0642 {
  strings:
    $key_0642 = { 55 2d [2] 71 23 [2] 5a 0f [2] 74 2d [2] 60 36 [2] 6f 2c [2] 71 31 [2] 73 30 [2] 68 36 [2] 74 31 [2] 68 1e }

  condition:
    any of them
}