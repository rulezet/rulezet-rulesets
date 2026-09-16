rule TTP_XOR_QUAD_CurrentVersionRun_4536 {
  strings:
    $key_4536 = { 16 59 [2] 32 57 [2] 19 7b [2] 37 59 [2] 23 42 [2] 2c 58 [2] 32 45 [2] 30 44 [2] 2b 42 [2] 37 45 [2] 2b 6a }

  condition:
    any of them
}