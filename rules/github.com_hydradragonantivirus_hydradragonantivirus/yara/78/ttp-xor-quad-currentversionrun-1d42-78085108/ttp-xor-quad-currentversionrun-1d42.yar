rule TTP_XOR_QUAD_CurrentVersionRun_1d42 {
  strings:
    $key_1d42 = { 4e 2d [2] 6a 23 [2] 41 0f [2] 6f 2d [2] 7b 36 [2] 74 2c [2] 6a 31 [2] 68 30 [2] 73 36 [2] 6f 31 [2] 73 1e }

  condition:
    any of them
}