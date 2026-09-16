rule TTP_XOR_QUAD_CurrentVersionRun_4523 {
  strings:
    $key_4523 = { 16 4c [2] 32 42 [2] 19 6e [2] 37 4c [2] 23 57 [2] 2c 4d [2] 32 50 [2] 30 51 [2] 2b 57 [2] 37 50 [2] 2b 7f }

  condition:
    any of them
}