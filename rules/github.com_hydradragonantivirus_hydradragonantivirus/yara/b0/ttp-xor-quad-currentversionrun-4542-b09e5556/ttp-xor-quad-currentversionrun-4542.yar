rule TTP_XOR_QUAD_CurrentVersionRun_4542 {
  strings:
    $key_4542 = { 16 2d [2] 32 23 [2] 19 0f [2] 37 2d [2] 23 36 [2] 2c 2c [2] 32 31 [2] 30 30 [2] 2b 36 [2] 37 31 [2] 2b 1e }

  condition:
    any of them
}