rule TTP_XOR_QUAD_CurrentVersionRun_4242 {
  strings:
    $key_4242 = { 11 2d [2] 35 23 [2] 1e 0f [2] 30 2d [2] 24 36 [2] 2b 2c [2] 35 31 [2] 37 30 [2] 2c 36 [2] 30 31 [2] 2c 1e }

  condition:
    any of them
}