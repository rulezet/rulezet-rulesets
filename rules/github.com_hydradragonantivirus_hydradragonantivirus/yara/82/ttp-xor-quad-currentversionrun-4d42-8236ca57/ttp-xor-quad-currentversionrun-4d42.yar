rule TTP_XOR_QUAD_CurrentVersionRun_4d42 {
  strings:
    $key_4d42 = { 1e 2d [2] 3a 23 [2] 11 0f [2] 3f 2d [2] 2b 36 [2] 24 2c [2] 3a 31 [2] 38 30 [2] 23 36 [2] 3f 31 [2] 23 1e }

  condition:
    any of them
}