rule TTP_XOR_QUAD_CurrentVersionRun_5e63 {
  strings:
    $key_5e63 = { 0d 0c [2] 29 02 [2] 02 2e [2] 2c 0c [2] 38 17 [2] 37 0d [2] 29 10 [2] 2b 11 [2] 30 17 [2] 2c 10 [2] 30 3f }

  condition:
    any of them
}