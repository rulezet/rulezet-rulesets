rule TTP_XOR_QUAD_CurrentVersionRun_5d42 {
  strings:
    $key_5d42 = { 0e 2d [2] 2a 23 [2] 01 0f [2] 2f 2d [2] 3b 36 [2] 34 2c [2] 2a 31 [2] 28 30 [2] 33 36 [2] 2f 31 [2] 33 1e }

  condition:
    any of them
}