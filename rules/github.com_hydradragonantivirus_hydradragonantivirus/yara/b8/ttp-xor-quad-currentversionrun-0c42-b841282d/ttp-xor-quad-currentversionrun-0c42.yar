rule TTP_XOR_QUAD_CurrentVersionRun_0c42 {
  strings:
    $key_0c42 = { 5f 2d [2] 7b 23 [2] 50 0f [2] 7e 2d [2] 6a 36 [2] 65 2c [2] 7b 31 [2] 79 30 [2] 62 36 [2] 7e 31 [2] 62 1e }

  condition:
    any of them
}