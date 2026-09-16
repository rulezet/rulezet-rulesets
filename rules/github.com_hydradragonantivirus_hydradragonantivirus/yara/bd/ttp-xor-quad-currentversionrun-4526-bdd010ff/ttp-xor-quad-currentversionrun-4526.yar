rule TTP_XOR_QUAD_CurrentVersionRun_4526 {
  strings:
    $key_4526 = { 16 49 [2] 32 47 [2] 19 6b [2] 37 49 [2] 23 52 [2] 2c 48 [2] 32 55 [2] 30 54 [2] 2b 52 [2] 37 55 [2] 2b 7a }

  condition:
    any of them
}