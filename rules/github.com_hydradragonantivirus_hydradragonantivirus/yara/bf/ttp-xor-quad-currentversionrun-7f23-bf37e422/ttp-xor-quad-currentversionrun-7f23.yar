rule TTP_XOR_QUAD_CurrentVersionRun_7f23 {
  strings:
    $key_7f23 = { 2c 4c [2] 08 42 [2] 23 6e [2] 0d 4c [2] 19 57 [2] 16 4d [2] 08 50 [2] 0a 51 [2] 11 57 [2] 0d 50 [2] 11 7f }

  condition:
    any of them
}