rule TTP_XOR_QUAD_CurrentVersionRun_1842 {
  strings:
    $key_1842 = { 4b 2d [2] 6f 23 [2] 44 0f [2] 6a 2d [2] 7e 36 [2] 71 2c [2] 6f 31 [2] 6d 30 [2] 76 36 [2] 6a 31 [2] 76 1e }

  condition:
    any of them
}